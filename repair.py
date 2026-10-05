#!/usr/bin/env python3
"""
Paso 1 — Generar UNA reparación por caso con la API de OpenAI y CONGELARLA.

Para cada caso de results/cases.txt:
  1. Lee el código vulnerable de vul4py/workspaces/<id>/vulnerable/
     (NUNCA lee fixed/, ni resultados de tests, ni Semgrep).
  2. Construye el prompt obligatorio + el código fuente.
  3. Llama a la Responses API por HTTPS y mide la latencia extremo a extremo.
  4. Extrae claimed_success, confidence y patch (salida estructurada JSON).
  5. Guarda y CONGELA: prompt.txt, llm_response.json, patch.diff, freeze.json
     (hash SHA-256 + permisos de solo lectura).

Si un caso ya está congelado, NO se vuelve a llamar al LLM (un solo intento).
Si la API falla (DNS, 401, 429, 5xx, timeout...) no hubo respuesta del modelo:
se registra el error y el caso queda sin congelar.

Uso:
    python3 repair.py                 # todos los casos de results/cases.txt
    python3 repair.py --case CVE-XXXX-YYYY
"""
import argparse
import datetime as dt
import hashlib
import json
import os
import re
import socket
import stat
import sys
import time
from pathlib import Path

import config as C

SKIP_DIRS = {".venv", "venv", ".git", "__pycache__", ".pytest_cache", "build", "dist",
             "backported_tests", "backported_support", "docs", "doc", "examples"}


# ---------------------------------------------------------------------------
# 1. Código vulnerable
# ---------------------------------------------------------------------------
def is_test_path(p: str) -> bool:
    parts = p.lower().split("/")
    name = parts[-1]
    return (any(x in ("test", "tests", "testing") for x in parts[:-1])
            or name.startswith("test_") or name.endswith("_test.py") or name == "conftest.py")


def collect_source(case_id: str):
    """Devuelve [(ruta_relativa, contenido)] del proyecto VULNERABLE.

    Prioriza meta.json["new_code_files"] (archivos de código que Vul4Py indica
    como relevantes; es la misma localización que usa el baseline de Vul4Py).
    Solo se lee el CONTENIDO de vulnerable/, nunca de fixed/.
    """
    case_dir = C.WORKSPACES / case_id
    vuln_dir = case_dir / "vulnerable"
    meta = json.loads((case_dir / "meta.json").read_text(encoding="utf-8"))

    candidates = [p for p in meta.get("new_code_files", []) if not is_test_path(p)]
    if not candidates:  # respaldo: todos los .py no-test del proyecto
        for path in sorted(vuln_dir.rglob("*.py")):
            rel = path.relative_to(vuln_dir).as_posix()
            if any(part in SKIP_DIRS for part in rel.split("/")) or is_test_path(rel):
                continue
            candidates.append(rel)

    files, used = [], 0
    for rel in candidates:
        if len(files) >= C.MAX_CONTEXT_FILES:
            break
        full = vuln_dir / rel
        if not full.is_file():
            continue
        text = full.read_text(encoding="utf-8", errors="replace")
        if used + len(text) > C.MAX_CONTEXT_CHARS:
            continue
        files.append((rel, text))
        used += len(text)
    return files, meta


def build_prompt(case_id: str, meta: dict, files) -> str:
    repo = (meta.get("repo_url") or "").rstrip("/").split("/")[-1]
    parts = [C.REQUIRED_PROMPT, "", f"Project: {repo}",
             "Paths below are relative to the project root (use a/ and b/ prefixes in the diff).", ""]
    for rel, text in files:
        parts += [f"--- FILE: {rel} ---", text.rstrip("\n"), f"--- END FILE: {rel} ---", ""]
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# 2. Llamada HTTPS a la API
# ---------------------------------------------------------------------------
def classify_error(exc: Exception) -> str:
    import openai
    if isinstance(exc, openai.APITimeoutError):
        return "timeout"
    if isinstance(exc, openai.APIConnectionError):
        # Recorre la cadena de excepciones: si la raíz es socket.gaierror,
        # falló la resolución DNS (getaddrinfo) antes de abrir la conexión TCP.
        cause, seen = exc, set()
        while cause is not None and id(cause) not in seen:
            seen.add(id(cause))
            if isinstance(cause, socket.gaierror) or any(
                    s in repr(cause) for s in ("Name or service not known", "getaddrinfo",
                                               "Temporary failure in name resolution")):
                return "dns_error"
            cause = cause.__cause__ or cause.__context__
        return "connection_error"
    if isinstance(exc, openai.APIStatusError):
        code = exc.status_code
        return "http_5xx" if code >= 500 else f"http_{code}"
    return type(exc).__name__


TRANSIENT = {"timeout", "connection_error", "dns_error", "http_429", "http_5xx"}


def call_api(prompt: str) -> dict:
    """Llama a la Responses API. Devuelve un dict con la respuesta y medidas de red."""
    from openai import OpenAI

    out = {"api_success": False, "error_type": "", "error_message": "", "attempts": []}
    if not os.environ.get("OPENAI_API_KEY"):
        out["error_type"] = "missing_api_key"
        return out

    # max_retries=0: controlamos los reintentos nosotros para medir cada intento.
    client = OpenAI(api_key=os.environ["OPENAI_API_KEY"], timeout=C.API_TIMEOUT_S, max_retries=0)

    for attempt in range(1, C.MAX_TRANSPORT_RETRIES + 2):
        rec = {"attempt": attempt, "started_at": dt.datetime.now(dt.timezone.utc).isoformat()}
        start = time.perf_counter()                       # justo antes de la petición
        try:
            raw = client.responses.with_raw_response.create(
                model=C.MODEL,
                input=prompt,
                text={"format": {"type": "json_schema", "name": "repair_result",
                                 "schema": C.RESPONSE_SCHEMA, "strict": True}},
            )
            end = time.perf_counter()                     # respuesta recibida
            resp = raw.parse()
            rec.update(latency_ms=round((end - start) * 1000, 1),
                       http_status=getattr(raw, "status_code", 200),
                       request_id=raw.headers.get("x-request-id"),
                       server_processing_ms=raw.headers.get("openai-processing-ms"))
            out["attempts"].append(rec)
            usage = getattr(resp, "usage", None)
            out.update(
                api_success=True,
                error_type="",            # un error transitorio previo ya no aplica
                error_message="",
                latency_ms=rec["latency_ms"],
                http_status=rec["http_status"],
                request_id=rec["request_id"],
                server_processing_ms=rec["server_processing_ms"],
                input_tokens=getattr(usage, "input_tokens", None),
                output_tokens=getattr(usage, "output_tokens", None),
                output_text=resp.output_text,
                raw_response=resp.model_dump(mode="json"),
            )
            return out
        except Exception as exc:  # noqa: BLE001
            end = time.perf_counter()
            etype = classify_error(exc)
            rec.update(latency_ms=round((end - start) * 1000, 1), error_type=etype,
                       http_status=getattr(exc, "status_code", None), error_message=str(exc)[:500])
            out["attempts"].append(rec)
            out.update(error_type=etype, error_message=str(exc)[:500], latency_ms=rec["latency_ms"])
            print(f"    [!] intento {attempt}: {etype} ({rec['latency_ms']} ms)", file=sys.stderr)
            if etype not in TRANSIENT or attempt > C.MAX_TRANSPORT_RETRIES:
                return out
            time.sleep(2 ** attempt)  # backoff exponencial (2 s, 4 s)
    return out


# ---------------------------------------------------------------------------
# 3. Parseo de la respuesta
# ---------------------------------------------------------------------------
def parse_llm_json(text: str) -> dict:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        m = re.search(r"\{.*\}", text, re.S)   # respaldo si vino con texto alrededor
        if not m:
            raise
        return json.loads(m.group(0))


def normalize_patch(patch: str) -> str:
    """Normalización mecánica (no es edición manual): quita fences ``` y
    asegura salto de línea final, que `git apply` exige."""
    s = patch.strip("\n")
    if s.lstrip().startswith("```"):
        lines = s.strip().splitlines()[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        s = "\n".join(lines)
    return s + "\n"


# ---------------------------------------------------------------------------
# 4. Congelar
# ---------------------------------------------------------------------------
def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def freeze(run_dir: Path):
    files = ["prompt.txt", "llm_response.json", "patch.diff"]
    manifest = {
        "frozen_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "sha256": {f: sha256(run_dir / f) for f in files},
        "note": "Response frozen BEFORE any Vul4Py verification. Do not edit.",
    }
    (run_dir / "freeze.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    for f in files + ["freeze.json"]:
        os.chmod(run_dir / f, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)  # 0444


def is_frozen(case_id: str) -> bool:
    return (C.RUNS / case_id / "freeze.json").exists()


# ---------------------------------------------------------------------------
def repair_case(case_id: str):
    run_dir = C.RUNS / case_id
    if is_frozen(case_id):
        print(f"[=] {case_id}: ya congelado; no se vuelve a llamar al LLM.")
        return
    run_dir.mkdir(parents=True, exist_ok=True)

    files, meta = collect_source(case_id)
    if not files:
        print(f"[!] {case_id}: no encontré código fuente para enviar.", file=sys.stderr)
    prompt = build_prompt(case_id, meta, files)
    (run_dir / "prompt.txt").write_text(prompt, encoding="utf-8")

    print(f"[>] {case_id}: {len(files)} archivos, {len(prompt):,} caracteres -> {C.MODEL}")
    api = call_api(prompt)

    record = {
        "student_id": C.STUDENT_ID,
        "case_id": case_id,
        "model": C.MODEL,
        "timestamp": dt.datetime.now(dt.timezone.utc).isoformat(),
        "context_files": [r for r, _ in files],
        "api_success": api["api_success"],
        "error_type": api.get("error_type", ""),
        "error_message": api.get("error_message", ""),
        "latency_ms": api.get("latency_ms"),
        "http_status": api.get("http_status"),
        "request_id": api.get("request_id"),
        "server_processing_ms": api.get("server_processing_ms"),
        "input_tokens": api.get("input_tokens"),
        "output_tokens": api.get("output_tokens"),
        "attempts": api["attempts"],
        "claimed_success": None,
        "confidence": None,
        "patch_raw": None,
        "warnings": [],
        "raw_output_text": api.get("output_text"),
        "raw_response": api.get("raw_response"),
    }

    if api["api_success"]:
        try:
            data = parse_llm_json(api["output_text"])
            record["claimed_success"] = bool(data["claimed_success"])
            record["confidence"] = float(data["confidence"])
            record["patch_raw"] = data["patch"]
            if not 0.0 <= record["confidence"] <= 1.0:
                record["warnings"].append("confidence outside [0,1]")
            if not data["patch"].strip():
                record["warnings"].append("empty patch")
        except Exception as exc:  # noqa: BLE001
            record["error_type"] = "parse_error"
            record["error_message"] = str(exc)[:500]

    (run_dir / "llm_response.json").write_text(json.dumps(record, indent=2, ensure_ascii=False),
                                               encoding="utf-8")

    if record["patch_raw"] is not None:
        (run_dir / "patch.diff").write_text(normalize_patch(record["patch_raw"]), encoding="utf-8")
        freeze(run_dir)
        print(f"[✓] {case_id}: claimed_success={record['claimed_success']} "
              f"confidence={record['confidence']} latency={record['latency_ms']} ms  -> CONGELADO")
    elif api["api_success"]:
        # El modelo respondió pero sin JSON válido: también es su único intento.
        (run_dir / "patch.diff").write_text("", encoding="utf-8")
        freeze(run_dir)
        print(f"[✗] {case_id}: respuesta no parseable -> congelado como parse_error")
    else:
        print(f"[✗] {case_id}: API falló ({record['error_type']}); sin respuesta del modelo, no se congela.")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--case", help="un solo caso")
    args = ap.parse_args()
    cases = [args.case] if args.case else [l.strip() for l in C.CASES_FILE.read_text().splitlines() if l.strip()]
    for cid in cases:
        repair_case(cid)


if __name__ == "__main__":
    main()
