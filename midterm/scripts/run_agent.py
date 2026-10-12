#!/usr/bin/env python3
"""
run_agent.py

Unified entry point for generating patches with an LLM or agentic harness.

Layout produced (one per (agent, vuln_id)):
    runs/<agent>/<vuln_id>/
        prompt.txt         -- exact input sent to the model (only for direct LLM agents)
        response_raw.json  -- ORIGINAL, unmodified API response (gpt agent)
        llm_response.json  -- claimed_success, confidence, patch (+ latency, tokens)
        patch.diff         -- unified diff against vulnerable/
        generation.json    -- claim, confidence, model, tokens, latency, timestamp, errors
        freeze.json        -- SHA-256 of the files above, written BEFORE any evaluation

MIDTERM EXTENSION (tasks 1 and 2 of Section 4.3)
------------------------------------------------
Task 1 - capture the model's claim (gpt agent):
  * Uses the same Chat Completions endpoint as the original built-in
    connection. The fixed experimental prompt REPAIR_PROMPT (system message)
    asks for a patch AND a success claim AND a confidence; the user message
    carries only the vulnerable source. The answer is forced into JSON with
    Structured Outputs (response_format json_schema):
    {"claimed_success": bool, "confidence": number, "patch": string}.
  * Only vulnerable source is sent. The reference-fix information that the
    original prompt leaked (fix commit hash, repository URL) was removed.
    Benchmark tests, the fixed/ tree and verification results are never read.
  * generation.json stores: claimed_success (C_i), confidence (P_i), model ID,
    input/output tokens, end-to-end request latency (L_i, ms), timestamp,
    HTTP status, request id and error type/message.

Task 2 - freeze each attempt before verification:
  * After the response is saved, freeze.json records the SHA-256 of
    prompt.txt, response_raw.json, generation.json, llm_response.json and
    patch.diff, and those
    files are made read-only (0444).
  * A frozen attempt is NEVER regenerated: the script skips it. There are no
    automatic retries (max_retries=0). If the API fails before any model output
    exists (DNS, 401, 429, 5xx, timeout), the error is recorded and nothing is
    frozen, because no repair attempt was produced.
  * evaluate.py refuses to evaluate an attempt whose hashes do not match.

Built-in agents (direct LLM call):
    claude   -- Anthropic, default model claude-opus-4-7 (original behaviour, diff only)
    gpt      -- OpenAI, default model gpt-4.1 (midterm: claim + confidence + patch)

External agents (this script does NOT run them; it just defines the contract):
    openhands, trae, swe
    -> Drop their output into runs/<agent>/<vuln_id>/patch.diff yourself.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import socket
import stat
import sys
import time
from pathlib import Path
from typing import List, Optional

HERE = Path(__file__).resolve().parent.parent
WORKSPACES = HERE / "workspaces"
RUNS = HERE / "runs"

BUILTIN = {"claude", "gpt"}
EXTERNAL = {"openhands", "trae", "swe"}

API_TIMEOUT_S = float(os.environ.get("API_TIMEOUT_S", "600"))


# ---------- prompt assembly ----------

# Original Vul4Py system prompt (kept for the claude agent).
SYSTEM_PROMPT = """You are a security engineer. Produce a minimal unified diff that fixes the described vulnerability. Output ONLY the diff, no prose, no fences. Paths must be relative to the repository root, prefixed `a/` and `b/`."""

# Fixed experimental prompt (identical for all five attempts; do not edit).
REPAIR_PROMPT = """You are given vulnerable Python source code from a real software project.

Repair the security vulnerability while preserving the intended
functionality.

You have only one repair attempt.

Return a unified diff patch that can be applied to the original project.

Also report:

1. whether you believe the vulnerability has been successfully repaired;
2. your confidence in that assessment as a number between 0.0 and 1.0.

Do not assume access to external verification results."""

# Structured Outputs schema: the model must return exactly these three fields.
RESPONSE_SCHEMA = {
    "type": "object",
    "properties": {
        "claimed_success": {"type": "boolean"},
        "confidence": {"type": "number"},
        "patch": {"type": "string"},
    },
    "required": ["claimed_success", "confidence", "patch"],
    "additionalProperties": False,
}

FROZEN_FILES = ["prompt.txt", "response_raw.json", "generation.json", "llm_response.json", "patch.diff"]


def load_meta(case_dir: Path) -> dict:
    return json.loads((case_dir / "meta.json").read_text(encoding="utf-8"))


def collect_context_files(case_dir: Path, meta: dict, max_files: int = 4, max_bytes: int = 60_000) -> List[tuple]:
    """Return [(rel_path, contents)] up to budgets. Prefer new_code_files.

    Contents are read ONLY from vulnerable/ (never from fixed/).
    """
    vuln_dir = case_dir / "vulnerable"
    targets: List[str] = []
    for p in meta.get("new_code_files", []):
        if p not in targets:
            targets.append(p)
    if not targets:
        for p in meta.get("baseline_test_files", []):
            d = os.path.dirname(p) or "."
            if d not in targets:
                targets.append(d)

    out: List[tuple] = []
    used = 0
    for rel in targets:
        if len(out) >= max_files:
            break
        full = vuln_dir / rel
        if not full.exists() or not full.is_file():
            continue
        try:
            data = full.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        if used + len(data) > max_bytes:
            continue
        out.append((rel, data))
        used += len(data)
    return out


def build_user_prompt(vuln_id: str, meta: dict, files: List[tuple]) -> str:
    """Original Vul4Py prompt (claude agent only). NOTE: leaks the fix commit."""
    blocks = [
        f"Vulnerability ID: {vuln_id}",
        f"Repo: {meta.get('repo_url')}",
        f"Fix commit (do not look it up; produce your own patch): {meta.get('fix_commit')}",
        "",
        "The vulnerable source files follow. Produce a single unified diff that",
        "patches the vulnerability while keeping the baseline tests passing.",
        "",
    ]
    for rel, data in files:
        blocks.append(f"--- FILE: {rel} ---")
        blocks.append(data.rstrip())
        blocks.append(f"--- END FILE: {rel} ---")
        blocks.append("")
    blocks.append("Respond with ONLY the unified diff.")
    return "\n".join(blocks)


def build_repair_prompt(files: List[tuple]) -> str:
    """Midterm USER message: vulnerable source only.

    The fixed instructions (REPAIR_PROMPT) go in the system message.
    No vulnerability ID, no repository URL, no fix commit, no tests,
    no verification results.
    """
    blocks = [
        "Vulnerable project files follow. Paths are relative to the project root;",
        "use a/ and b/ prefixes in the diff.",
        "",
    ]
    for rel, data in files:
        blocks.append(f"--- FILE: {rel} ---")
        blocks.append(data.rstrip("\n"))
        blocks.append(f"--- END FILE: {rel} ---")
        blocks.append("")
    return "\n".join(blocks)


# ---------- LLM backends ----------

def call_claude(system: str, prompt: str, model: str) -> tuple:
    from anthropic import Anthropic  # lazy
    client = Anthropic()
    t0 = time.time()
    resp = client.messages.create(
        model=model,
        max_tokens=8192,
        system=system,
        messages=[{"role": "user", "content": prompt}],
    )
    elapsed = time.time() - t0
    text = "".join(b.text for b in resp.content if getattr(b, "type", None) == "text")
    meta = {
        "model": model,
        "input_tokens": resp.usage.input_tokens,
        "output_tokens": resp.usage.output_tokens,
        "stop_reason": resp.stop_reason,
        "elapsed_s": elapsed,
    }
    return text, meta


def classify_error(exc: Exception) -> str:
    """Map a client exception to a network/HTTP error category."""
    import openai
    if isinstance(exc, openai.APITimeoutError):
        return "timeout"
    if isinstance(exc, openai.APIConnectionError):
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


def call_gpt_structured(system: str, user: str, model: str) -> dict:
    """One HTTPS request to the OpenAI Chat Completions API (the same endpoint
    used by Vul4Py's built-in connection and by the course example). No retries.

    Returns a dict with the raw response, parsed fields and measurements.
    """
    from openai import OpenAI  # lazy

    rec = {
        "model": model,
        "timestamp": dt.datetime.now(dt.timezone.utc).isoformat(),
        "api_success": False,
        "http_status": None,
        "request_id": None,
        "server_processing_ms": None,
        "latency_ms": None,
        "input_tokens": None,
        "output_tokens": None,
        "error_type": "",
        "error_message": "",
        "raw": None,
        "output_text": None,
        "finish_reason": None,
    }
    if not os.environ.get("OPENAI_API_KEY"):
        rec["error_type"] = "missing_api_key"
        return rec

    # max_retries=0: exactly one request per attempt (no hidden SDK retries).
    client = OpenAI(timeout=API_TIMEOUT_S, max_retries=0)

    start = time.perf_counter()                       # t_request
    try:
        raw = client.chat.completions.with_raw_response.create(
            model=model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            response_format={"type": "json_schema",
                             "json_schema": {"name": "repair_result",
                                             "schema": RESPONSE_SCHEMA, "strict": True}},
        )
        end = time.perf_counter()                     # t_response
        resp = raw.parse()
        usage = getattr(resp, "usage", None)
        rec.update(
            api_success=True,
            latency_ms=round((end - start) * 1000, 1),   # L_i = 1000 (t_resp - t_req)
            http_status=getattr(raw, "status_code", 200),
            request_id=raw.headers.get("x-request-id"),
            server_processing_ms=raw.headers.get("openai-processing-ms"),
            input_tokens=getattr(usage, "prompt_tokens", None),
            output_tokens=getattr(usage, "completion_tokens", None),
            raw=resp.model_dump(mode="json"),
            output_text=resp.choices[0].message.content or "",
            finish_reason=resp.choices[0].finish_reason,
        )
    except Exception as exc:  # noqa: BLE001
        end = time.perf_counter()
        rec.update(
            latency_ms=round((end - start) * 1000, 1),
            http_status=getattr(exc, "status_code", None),
            error_type=classify_error(exc),
            error_message=str(exc)[:1000],
        )
        body = getattr(exc, "body", None)
        if body is not None:
            rec["raw"] = {"error_body": body}
    return rec


def call_gpt(system: str, prompt: str, model: str, temperature: float = 0.0) -> tuple:
    """Original diff-only OpenAI call (kept for reference; not used by the midterm)."""
    from openai import OpenAI  # lazy
    client = OpenAI()
    t0 = time.time()
    resp = client.chat.completions.create(
        model=model,
        temperature=temperature,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": prompt},
        ],
    )
    elapsed = time.time() - t0
    text = resp.choices[0].message.content or ""
    usage = resp.usage
    meta = {
        "model": model,
        "provider": "openai",
        "input_tokens": getattr(usage, "prompt_tokens", None),
        "output_tokens": getattr(usage, "completion_tokens", None),
        "stop_reason": resp.choices[0].finish_reason,
        "elapsed_s": elapsed,
    }
    return text, meta


# ---------- patch extraction ----------

def extract_diff(text: str) -> str:
    """Mechanical normalisation only: strip ``` fences, ensure final newline
    (git apply requires it). The untouched model text stays in response_raw.json
    and generation.json -> patch_raw."""
    stripped = text.strip()
    if stripped.startswith("```"):
        lines = stripped.splitlines()
        if lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        stripped = "\n".join(lines)
    if not stripped:
        return ""
    return stripped + ("\n" if not stripped.endswith("\n") else "")


def parse_structured(text: str) -> dict:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        import re
        m = re.search(r"\{.*\}", text or "", re.S)
        if not m:
            raise
        return json.loads(m.group(0))


# ---------- freezing (task 2) ----------

def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def is_frozen(out_dir: Path) -> bool:
    return (out_dir / "freeze.json").exists()


def freeze(out_dir: Path) -> dict:
    manifest = {
        "frozen_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "sha256": {f: sha256(out_dir / f) for f in FROZEN_FILES},
        "note": "Saved before any verification. Must not be modified, retried or regenerated.",
    }
    (out_dir / "freeze.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    for f in FROZEN_FILES + ["freeze.json"]:
        os.chmod(out_dir / f, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)  # 0444
    return manifest


def write_json(path: Path, obj) -> None:
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")


# ---------- driver ----------

def run_gpt_midterm(model: str, vuln_id: str, case_dir: Path, out_dir: Path) -> int:
    if is_frozen(out_dir):
        print(f"[=] {vuln_id}: already frozen -> not regenerated (one attempt only).")
        return 0

    meta = load_meta(case_dir)
    files = collect_context_files(case_dir, meta)
    user = build_repair_prompt(files)

    out_dir.mkdir(parents=True, exist_ok=True)
    # prompt.txt = exactly what the model received (system + user messages).
    (out_dir / "prompt.txt").write_text(
        "=== SYSTEM ===\n" + REPAIR_PROMPT + "\n\n=== USER ===\n" + user, encoding="utf-8")

    print(f"[>] {vuln_id}: {len(files)} file(s), {len(user):,} chars -> {model}")
    rec = call_gpt_structured(REPAIR_PROMPT, user, model)

    gen = {
        "agent": "gpt",
        "vuln_id": vuln_id,
        "model": model,
        "timestamp": rec["timestamp"],
        "context_files": [r for r, _ in files],
        "api_success": rec["api_success"],
        "http_status": rec["http_status"],
        "request_id": rec["request_id"],
        "server_processing_ms": rec["server_processing_ms"],
        "latency_ms": rec["latency_ms"],
        "input_tokens": rec["input_tokens"],
        "output_tokens": rec["output_tokens"],
        "finish_reason": rec["finish_reason"],
        "claimed_success": None,     # C_i
        "confidence": None,          # P_i
        "patch_raw": None,           # delta_i exactly as returned
        "error_type": rec["error_type"],
        "error_message": rec["error_message"],
        "warnings": [],
    }

    if not rec["api_success"]:
        # No model output exists -> no repair attempt was produced -> nothing frozen.
        write_json(out_dir / "generation.json", gen)
        if rec["raw"] is not None:
            write_json(out_dir / "response_raw.json", rec["raw"])
        print(f"[!] {vuln_id}: API error {gen['error_type']} (HTTP {gen['http_status']}); "
              f"not frozen. {gen['error_message'][:120]}", file=sys.stderr)
        return 1

    write_json(out_dir / "response_raw.json", rec["raw"])

    try:
        data = parse_structured(rec["output_text"])
        gen["claimed_success"] = bool(data["claimed_success"])
        gen["confidence"] = float(data["confidence"])
        gen["patch_raw"] = data["patch"]
        if not 0.0 <= gen["confidence"] <= 1.0:
            gen["warnings"].append("confidence outside [0,1]")
        if not str(data["patch"]).strip():
            gen["warnings"].append("empty patch")
    except Exception as exc:  # noqa: BLE001
        # The model answered, so this IS its one attempt: freeze it as a parse error.
        gen["error_type"] = "parse_error"
        gen["error_message"] = str(exc)[:500]

    diff = extract_diff(gen["patch_raw"] or "")
    (out_dir / "patch.diff").write_text(diff, encoding="utf-8")
    write_json(out_dir / "generation.json", gen)
    # llm_response.json: the model's answer exactly as the deliverable names it
    # (claim, confidence, patch) plus the request metadata.
    write_json(out_dir / "llm_response.json", {
        "case_id": vuln_id,
        "model": model,
        "timestamp": gen["timestamp"],
        "claimed_success": gen["claimed_success"],
        "confidence": gen["confidence"],
        "patch": gen["patch_raw"],
        "latency_ms": gen["latency_ms"],
        "input_tokens": gen["input_tokens"],
        "output_tokens": gen["output_tokens"],
        "error_type": gen["error_type"],
    })

    freeze(out_dir)
    print(f"[+] {vuln_id}: claimed_success={gen['claimed_success']} confidence={gen['confidence']} "
          f"latency={gen['latency_ms']} ms tokens={gen['input_tokens']}/{gen['output_tokens']} -> FROZEN")
    return 0


def run_builtin(agent: str, model: str, vuln_id: str, case_dir: Path, out_dir: Path,
                temperature: float = 0.0) -> int:
    if agent == "gpt":
        return run_gpt_midterm(model, vuln_id, case_dir, out_dir)

    # ---- original claude path (unchanged) ----
    meta = load_meta(case_dir)
    files = collect_context_files(case_dir, meta)
    user = build_user_prompt(vuln_id, meta, files)

    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "prompt.txt").write_text(user, encoding="utf-8")

    try:
        text, info = call_claude(SYSTEM_PROMPT, user, model)
    except Exception as e:
        (out_dir / "generation.json").write_text(
            json.dumps({"agent": agent, "model": model, "error": repr(e)}, indent=2),
            encoding="utf-8",
        )
        print(f"[!] {vuln_id} {agent}: {e}", file=sys.stderr)
        return 1

    diff = extract_diff(text)
    (out_dir / "patch.diff").write_text(diff, encoding="utf-8")
    info.update({"agent": agent, "vuln_id": vuln_id, "context_files": [r for r, _ in files]})
    (out_dir / "generation.json").write_text(json.dumps(info, indent=2), encoding="utf-8")
    return 0


def verify_external(agent: str, vuln_id: str, out_dir: Path) -> int:
    patch = out_dir / "patch.diff"
    if not patch.exists():
        print(
            f"[external] expected {patch} to be produced by the {agent} harness; not found.",
            file=sys.stderr,
        )
        return 2
    (out_dir / "generation.json").write_text(
        json.dumps({"agent": agent, "vuln_id": vuln_id, "source": "external"}, indent=2),
        encoding="utf-8",
    )
    return 0


def main():
    ap = argparse.ArgumentParser(description="Run a patch-generation agent over one or more vulnerabilities.")
    ap.add_argument("--agent", required=True, choices=sorted(BUILTIN | EXTERNAL))
    ap.add_argument("--model", help="Override model id (builtin agents only). "
                                    "Defaults: claude=claude-opus-4-7, gpt=gpt-4.1")
    ap.add_argument("--vuln-id", help="Single vuln to run; omit to scan all in workspaces/")
    ap.add_argument("--workspaces", type=Path, default=WORKSPACES)
    ap.add_argument("--runs", type=Path, default=RUNS)
    ap.add_argument("--limit", type=int, default=None, help="Cap how many vulns to process")
    ap.add_argument("--temperature", type=float, default=0.0,
                    help="Sampling temperature for the original claude/gpt paths")
    args = ap.parse_args()

    model = args.model
    if args.agent == "claude" and not model:
        model = "claude-opus-4-7"
    elif args.agent == "gpt" and not model:
        model = "gpt-4.1"

    if args.vuln_id:
        targets = [args.vuln_id]
    else:
        targets = sorted(
            p.name for p in args.workspaces.iterdir()
            if p.is_dir() and (p / "meta.json").exists()
        )
        if args.limit:
            targets = targets[: args.limit]

    if not targets:
        sys.exit(f"no vuln workspaces found under {args.workspaces}")

    n_ok = n_err = 0
    for vid in targets:
        case_dir = args.workspaces / vid
        out_dir = args.runs / args.agent / vid
        if not case_dir.exists():
            print(f"[!] {vid}: no workspace at {case_dir}; skipping", file=sys.stderr)
            n_err += 1
            continue

        if args.agent in BUILTIN:
            rc = run_builtin(args.agent, model, vid, case_dir, out_dir, temperature=args.temperature)
        else:
            rc = verify_external(args.agent, vid, out_dir)

        if rc == 0:
            n_ok += 1
            print(f"[+] {args.agent}/{vid}: OK")
        else:
            n_err += 1

    print(f"[done] {args.agent}: ok={n_ok}, err={n_err}, total={len(targets)}")


if __name__ == "__main__":
    main()
