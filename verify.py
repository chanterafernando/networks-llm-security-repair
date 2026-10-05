#!/usr/bin/env python3
"""
Paso 2 — Verificación independiente (Vul4Py) + medición secundaria (Semgrep).

Para cada caso CONGELADO:
  1. Comprueba que prompt.txt / llm_response.json / patch.diff no cambiaron
     desde el congelamiento (SHA-256 de freeze.json).
  2. Ejecuta el evaluador oficial:  vul4py/scripts/evaluate.py --agent student --vuln-id <id>
     -> runs/student/<id>/eval.json  (apply_ok, functional_rc, exploit_rc, plausible)
  3. Semgrep sobre los archivos relevantes ANTES (vulnerable/) y DESPUÉS (vulnerable/ + patch).
  4. Copia los artefactos a results/cases/<id>/ para versionarlos en GitHub.

Nada de esto se envía al LLM.

Uso:
    python3 verify.py
    python3 verify.py --case CVE-XXXX-YYYY --skip-semgrep
"""
import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import config as C

IGNORE = shutil.ignore_patterns(".venv", "__pycache__", ".pytest_cache",
                                "backported_tests", "backported_support")


def check_frozen(run_dir: Path) -> bool:
    manifest = json.loads((run_dir / "freeze.json").read_text(encoding="utf-8"))
    for name, digest in manifest["sha256"].items():
        actual = hashlib.sha256((run_dir / name).read_bytes()).hexdigest()
        if actual != digest:
            print(f"[!!] {run_dir.name}: {name} fue modificado después del congelamiento.", file=sys.stderr)
            return False
    return True


def run_vul4py_eval(case_id: str) -> dict:
    cmd = [sys.executable, "scripts/evaluate.py", "--agent", C.AGENT, "--vuln-id", case_id]
    print("    $", " ".join(cmd), flush=True)
    subprocess.run(cmd, cwd=C.VUL4PY)
    return json.loads((C.RUNS / case_id / "eval.json").read_text(encoding="utf-8"))


# --------------------------- Semgrep ---------------------------------------
def patched_files(patch_text: str):
    out = []
    for m in re.finditer(r"^\+\+\+ (?:b/)?(\S+)", patch_text, re.M):
        p = m.group(1)
        if p != "/dev/null" and p.endswith(".py") and p not in out:
            out.append(p)
    return out


def semgrep_count(tree: Path, targets, out_json: Path):
    targets = [t for t in targets if (tree / t).is_file()]
    if not targets:
        out_json.write_text(json.dumps({"results": [], "note": "no targets"}), encoding="utf-8")
        return 0
    cp = subprocess.run(["semgrep", "--config=auto", "--json", "--quiet", *targets],
                        cwd=tree, capture_output=True, text=True)
    out_json.write_text(cp.stdout or json.dumps({"error": cp.stderr[-2000:]}), encoding="utf-8")
    try:
        return len(json.loads(cp.stdout)["results"])
    except Exception:  # noqa: BLE001
        print(f"    [!] semgrep falló: {cp.stderr[-300:]}", file=sys.stderr)
        return None


def build_candidate(case_id: str, patch: Path):
    """Copia vulnerable/ y aplica el parche (el evaluador de Vul4Py borra su
    candidate al terminar, así que creamos uno propio solo para Semgrep)."""
    case_dir = C.WORKSPACES / case_id
    dst = case_dir / f"{C.AGENT}_semgrep_candidate"
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(case_dir / "vulnerable", dst, ignore=IGNORE)
    ok = subprocess.run(["git", "apply", "--whitespace=nowarn", str(patch.resolve())],
                        cwd=dst, capture_output=True).returncode == 0
    if not ok and shutil.which("patch"):
        ok = subprocess.run(["patch", "-p1", "-i", str(patch.resolve())],
                            cwd=dst, capture_output=True).returncode == 0
    return dst, ok


def run_semgrep(case_id: str, run_dir: Path) -> dict:
    resp = json.loads((run_dir / "llm_response.json").read_text(encoding="utf-8"))
    patch = run_dir / "patch.diff"
    targets = list(dict.fromkeys(resp.get("context_files", []) + patched_files(patch.read_text())))

    before = semgrep_count(C.WORKSPACES / case_id / "vulnerable", targets, run_dir / "semgrep_before.json")
    after = None
    if patch.stat().st_size > 0:
        cand, applied = build_candidate(case_id, patch)
        if applied:
            after = semgrep_count(cand, targets, run_dir / "semgrep_after.json")
        shutil.rmtree(cand, ignore_errors=True)
    summary = {"targets": targets, "semgrep_findings_before": before, "semgrep_findings_after": after}
    (run_dir / "semgrep_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


# ---------------------------------------------------------------------------
def archive(case_id: str, run_dir: Path):
    dst = C.ARCHIVE / case_id
    dst.mkdir(parents=True, exist_ok=True)
    for name in ["prompt.txt", "llm_response.json", "patch.diff", "freeze.json", "eval.json", "eval.log",
                 "semgrep_before.json", "semgrep_after.json", "semgrep_summary.json"]:
        src = run_dir / name
        if src.exists():
            target = dst / name
            if target.exists():
                target.chmod(0o644)
            shutil.copyfile(src, target)


def verify_case(case_id: str, skip_semgrep: bool):
    run_dir = C.RUNS / case_id
    if not (run_dir / "freeze.json").exists():
        print(f"[-] {case_id}: no hay respuesta congelada (¿falló la API?). Se omite la verificación.")
        if (run_dir / "llm_response.json").exists():
            archive(case_id, run_dir)
        return
    if not check_frozen(run_dir):
        sys.exit("[!!] Integridad del experimento comprometida. Abortando.")

    print(f"[>] {case_id}: verificación Vul4Py")
    ev = run_vul4py_eval(case_id)
    print(f"    apply={ev['apply_ok']} functional_rc={ev['functional_rc']} "
          f"exploit_rc={ev['exploit_rc']} plausible={ev['plausible']}")
    if not skip_semgrep:
        s = run_semgrep(case_id, run_dir)
        print(f"    semgrep before={s['semgrep_findings_before']} after={s['semgrep_findings_after']}")
    archive(case_id, run_dir)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--case")
    ap.add_argument("--skip-semgrep", action="store_true")
    args = ap.parse_args()
    cases = [args.case] if args.case else [l.strip() for l in C.CASES_FILE.read_text().splitlines() if l.strip()]
    for cid in cases:
        verify_case(cid, args.skip_semgrep)


if __name__ == "__main__":
    main()
