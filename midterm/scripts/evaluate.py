#!/usr/bin/env python3
"""
evaluate.py

For one or more agents, for one or more vulns:
  1. Fork the vulnerable/ checkout into <case>/<agent>_candidate/
  2. Apply runs/<agent>/<vuln_id>/patch.diff
  3. Install + run baseline functional tests (must still pass)
  4. Run exploit/regression tests (must now pass)
  5. Write runs/<agent>/<vuln_id>/eval.json with verdict

Original verdict fields (kept for backward compatibility):
    apply_ok            -- did the patch apply cleanly?
    functional_rc       -- exit code of baseline tests on candidate (0 = pass)
    exploit_rc          -- exit code of exploit tests on candidate
    plausible           -- apply_ok AND functional_rc in (0,999) AND exploit_rc == 0
    notes               -- error string if any

MIDTERM EXTENSION (task 3 of Section 4.3, plus the freeze check of task 2)
-------------------------------------------------------------------------
  * Before anything runs, the frozen attempt is checked: freeze.json must exist
    and the SHA-256 of prompt.txt / response_raw.json / generation.json /
    patch.diff must match. Otherwise nothing is evaluated (status=incomplete).
  * Per-attempt indicators of Section 3 are added to eval.json:
        A_i  patch applied                       (1/0)
        F_i  functional tests on the patched project passed   (1/0)
        S_i  security/exploit tests on the patched project passed (1/0)
        V_i  = A_i * F_i * S_i
        C_i, P_i, L_i copied from the frozen generation.json
        FA_i = C_i * (1 - V_i)
  * A patch that cannot be applied gives A=F=S=0 and the tests are NOT run.
  * Test failures are separated from incomplete verification:
        functional/exploit rc 999 (no tests)        -> incomplete (tests_missing)
        rc 5 / junit with 0 tests (nothing collected) -> incomplete (no_tests_collected)
        rc 124 (timeout)                             -> incomplete (timeout)
        no rc printed (install/setup crash)          -> incomplete (infra_error)
        rc 0 with >= 1 passed test                   -> pass (1)
        any other rc (tests failed / errored)        -> fail (0)
    The original `plausible` rule accepted rc 999 as a pass; `plausible` is kept
    only for comparison and is NOT used for V_i.
  * Incomplete attempts get V/FA = null and are reported separately.
  * Supporting logs (patch, functional, exploit, junit, install) are copied into
    runs/<agent>/<vuln_id>/logs/ before the candidate tree is removed.

This script wraps scripts/vul4py.py for actual setup / test / fork / patch work,
so the harness behavior matches the rest of the pipeline.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import List, Optional

HERE = Path(__file__).resolve().parent.parent
WORKSPACES = HERE / "workspaces"
RUNS = HERE / "runs"
VUL4PY = Path(__file__).resolve().parent / "vul4py.py"

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vul4py import _parse_junit  # noqa: E402  (reuse Vul4Py's own junit parser)

RC_TESTS_MISSING = 999
RC_TIMEOUT = 124
RC_NO_TESTS_COLLECTED = 5


def cleanup_candidate(case_dir: Path, dst_name: str):
    p = case_dir / dst_name
    if p.exists():
        shutil.rmtree(p, ignore_errors=True)


def run_vul4py(args: List[str], log_lines: list) -> subprocess.CompletedProcess:
    cmd = [sys.executable, str(VUL4PY)] + args
    log_lines.append("$ " + " ".join(cmd))
    cp = subprocess.run(cmd, capture_output=True, text=True)
    log_lines.append(f"[exit {cp.returncode}]")
    if cp.stdout:
        log_lines.append(cp.stdout)
    if cp.stderr:
        log_lines.append(cp.stderr)
    return cp


def parse_rc(stdout: str, marker: str) -> Optional[int]:
    for line in stdout.splitlines():
        if marker in line:
            try:
                return int(line.split(marker, 1)[1].strip().split()[0])
            except Exception:
                continue
    return None


# ---------------------------------------------------------------------------
# Midterm helpers
# ---------------------------------------------------------------------------

def check_frozen(run_dir: Path) -> Optional[str]:
    """Return None if the attempt is frozen and intact, else a reason string."""
    fz = run_dir / "freeze.json"
    if not fz.exists():
        return "not_frozen"
    manifest = json.loads(fz.read_text(encoding="utf-8"))
    for name, digest in manifest.get("sha256", {}).items():
        f = run_dir / name
        if not f.exists():
            return f"frozen_file_missing:{name}"
        if hashlib.sha256(f.read_bytes()).hexdigest() != digest:
            return f"integrity_violation:{name}"
    return None


def patch_applies(src_dir: Path, patch: Path) -> tuple:
    """A_i check without touching src_dir: git apply --check, then patch --dry-run.

    Uses the same two tools, in the same order, as vul4py.apply_unidiff_patch.
    """
    if patch.stat().st_size == 0 or not patch.read_text(errors="replace").strip():
        return False, "empty patch"
    cp = subprocess.run(["git", "apply", "--check", "--whitespace=nowarn", str(patch.resolve())],
                        cwd=src_dir, capture_output=True, text=True)
    if cp.returncode == 0:
        return True, "git apply --check ok"
    msg = cp.stderr.strip()
    if shutil.which("patch"):
        cp2 = subprocess.run(["patch", "-p1", "--dry-run", "-i", str(patch.resolve())],
                             cwd=src_dir, capture_output=True, text=True)
        if cp2.returncode == 0:
            return True, "patch -p1 --dry-run ok"
        msg += "\n" + (cp2.stdout + cp2.stderr).strip()
    return False, msg[-2000:]


def classify(rc: Optional[int], junit: Optional[dict]) -> tuple:
    """Map a test run to (indicator, incomplete_reason).

    indicator: 1 pass, 0 fail, None incomplete.
    """
    if rc is None:
        return None, "infra_error"
    if rc == RC_TESTS_MISSING:
        return None, "tests_missing"
    if rc == RC_TIMEOUT:
        return None, "timeout"
    if rc == RC_NO_TESTS_COLLECTED or (junit is not None and junit.get("tests", 0) == 0):
        return None, "no_tests_collected"
    if rc == 0:
        if junit is not None and junit.get("passed", 0) == 0:
            return None, "no_passing_tests"   # e.g. everything skipped
        return 1, ""
    return 0, ""


def junit_summary(j: Optional[dict]) -> Optional[dict]:
    if j is None:
        return None
    out = {k: j.get(k) for k in ("tests", "passed", "failed", "errored", "skipped")}
    out["failed_cases"] = [f"{c['classname']}::{c['name']}" for c in j.get("failed_cases", [])][:50]
    return out


def copy_logs(case_dir: Path, dst_name: str, run_dir: Path):
    """Keep supporting test logs as evidence (candidate tree is deleted afterwards)."""
    logs_src = case_dir / "logs"
    logs_dst = run_dir / "logs"
    logs_dst.mkdir(parents=True, exist_ok=True)
    for f in logs_src.glob(f"*{dst_name}*"):
        if f.is_file():
            shutil.copyfile(f, logs_dst / f.name)


def load_generation(run_dir: Path) -> dict:
    g = run_dir / "generation.json"
    return json.loads(g.read_text(encoding="utf-8")) if g.exists() else {}


# ---------------------------------------------------------------------------

def evaluate_one(workspaces: Path, runs: Path, agent: str, vuln_id: str) -> dict:
    case_dir = workspaces / vuln_id
    run_dir = runs / agent / vuln_id
    patch = run_dir / "patch.diff"
    eval_path = run_dir / "eval.json"
    log_path = run_dir / "eval.log"

    gen = load_generation(run_dir)
    claim = gen.get("claimed_success")
    verdict = {
        "agent": agent,
        "vuln_id": vuln_id,
        "model": gen.get("model"),
        # ---- original fields ----
        "apply_ok": False,
        "functional_rc": None,
        "exploit_rc": None,
        "plausible": False,
        "elapsed_s": None,
        "notes": "",
        # ---- Section 3 indicators ----
        "status": "incomplete",          # complete | incomplete
        "incomplete_reason": "",
        "C": None if claim is None else int(bool(claim)),
        "P": gen.get("confidence"),
        "L_ms": gen.get("latency_ms"),
        "A": None,
        "F": None,
        "S": None,
        "V": None,
        "FA": None,
        "apply_detail": "",
        "functional_junit": None,
        "exploit_junit": None,
        "llm_error_type": gen.get("error_type", ""),
    }
    log: list = []
    t0 = time.time()

    def finish(v: dict) -> dict:
        v["elapsed_s"] = round(time.time() - t0, 1)
        eval_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text("\n".join(log) + "\n", encoding="utf-8")
        eval_path.write_text(json.dumps(v, indent=2), encoding="utf-8")
        return v

    if not case_dir.exists() or not (case_dir / "meta.json").exists():
        verdict["notes"] = f"no workspace at {case_dir}"
        verdict["incomplete_reason"] = "no_workspace"
        return finish(verdict)
    if not patch.exists():
        verdict["notes"] = f"no patch at {patch}"
        verdict["incomplete_reason"] = "no_patch_file"
        return finish(verdict)

    # Task 2: only evaluate an intact, frozen attempt.
    frozen_problem = check_frozen(run_dir)
    if frozen_problem:
        verdict["notes"] = f"attempt not evaluated: {frozen_problem}"
        verdict["incomplete_reason"] = frozen_problem
        log.append(f"[!] {frozen_problem}")
        return finish(verdict)

    # ---- A_i: does the patch apply to the ORIGINAL project? ----
    ok, detail = patch_applies(case_dir / "vulnerable", patch)
    verdict["apply_detail"] = detail
    log.append(f"[apply-check] {ok}: {detail}")
    if not ok:
        verdict.update(A=0, F=0, S=0, V=0, status="complete",
                       notes="patch did not apply")
        verdict["FA"] = verdict["C"] * (1 - verdict["V"]) if verdict["C"] is not None else None
        return finish(verdict)

    dst_name = f"{agent}_candidate"
    cleanup_candidate(case_dir, dst_name)

    fork = run_vul4py(
        [
            "--workspace-root", str(workspaces),
            "--cve-id", vuln_id,
            "fork",
            "--src", "vulnerable",
            "--dst", dst_name,
            "--patch", str(patch.resolve()),
        ],
        log,
    )
    if fork.returncode != 0:
        # The dry-run said the patch applies, so a fork failure is infrastructure.
        verdict["notes"] = "fork failed after successful apply check"
        verdict["incomplete_reason"] = "fork_infra_error"
        copy_logs(case_dir, dst_name, run_dir)
        cleanup_candidate(case_dir, dst_name)
        return finish(verdict)

    verdict["apply_ok"] = True
    verdict["A"] = 1

    # ---- F_i: functional tests on the patched project ----
    func = run_vul4py(
        [
            "--workspace-root", str(workspaces),
            "--cve-id", vuln_id,
            "functional",
            "--target", dst_name,
        ],
        log,
    )
    func_rc = parse_rc(func.stdout, "rc=")
    verdict["functional_rc"] = func_rc
    fj = _parse_junit(case_dir / "logs" / f"functional_{dst_name}.junit.xml")
    verdict["functional_junit"] = junit_summary(fj)
    F, f_reason = classify(func_rc, fj)

    # ---- S_i: exploit/security tests on the SAME patched project ----
    expl = run_vul4py(
        [
            "--workspace-root", str(workspaces),
            "--cve-id", vuln_id,
            "exploit",
            "--targets", dst_name,
        ],
        log,
    )
    expl_rc = parse_rc(expl.stdout, f"{dst_name}: rc=")
    if expl_rc is None:
        expl_rc = parse_rc(expl.stdout, "rc=")
    verdict["exploit_rc"] = expl_rc
    ej = _parse_junit(case_dir / "logs" / f"exploit_{dst_name}.junit.xml")
    verdict["exploit_junit"] = junit_summary(ej)
    S, s_reason = classify(expl_rc, ej)

    # Original rule, kept only for comparison (accepts rc 999 = no tests).
    verdict["plausible"] = (
        verdict["apply_ok"]
        and (verdict["functional_rc"] in (0, 999))
        and (verdict["exploit_rc"] == 0)
    )

    verdict["F"], verdict["S"] = F, S
    reasons = [f"functional:{f_reason}" if f_reason else "", f"exploit:{s_reason}" if s_reason else ""]
    reasons = [r for r in reasons if r]

    if F is None or S is None:
        verdict["status"] = "incomplete"
        verdict["incomplete_reason"] = ";".join(reasons)
    else:
        verdict["status"] = "complete"
        verdict["V"] = verdict["A"] * F * S
        if verdict["C"] is not None:
            verdict["FA"] = verdict["C"] * (1 - verdict["V"])

    copy_logs(case_dir, dst_name, run_dir)
    cleanup_candidate(case_dir, dst_name)
    return finish(verdict)


def main():
    ap = argparse.ArgumentParser(description="Evaluate agent-produced patches against baseline + exploit tests.")
    ap.add_argument("--agent", required=True)
    ap.add_argument("--vuln-id", help="Single vuln; omit to evaluate every patch found.")
    ap.add_argument("--workspaces", type=Path, default=WORKSPACES)
    ap.add_argument("--runs", type=Path, default=RUNS)
    ap.add_argument("--limit", type=int, default=None)
    args = ap.parse_args()

    agent_dir = args.runs / args.agent
    if not agent_dir.exists():
        sys.exit(f"no runs for agent: {agent_dir}")

    if args.vuln_id:
        targets = [args.vuln_id]
    else:
        targets = sorted(p.name for p in agent_dir.iterdir() if (p / "patch.diff").exists())
        if args.limit:
            targets = targets[: args.limit]

    n_ver = n_inc = 0
    for vid in targets:
        v = evaluate_one(args.workspaces, args.runs, args.agent, vid)
        if v["status"] == "complete":
            flag = "VERIFIED" if v["V"] == 1 else "NOT_VERIFIED"
            n_ver += v["V"] == 1
        else:
            flag = f"INCOMPLETE({v['incomplete_reason']})"
            n_inc += 1
        print(
            f"  {args.agent}/{vid}: {flag} C={v['C']} A={v['A']} F={v['F']} S={v['S']} "
            f"V={v['V']} FA={v['FA']} func_rc={v['functional_rc']} expl_rc={v['exploit_rc']} "
            f"({v['elapsed_s']}s)"
        )
    print(f"[done] {args.agent}: verified {n_ver}/{len(targets)}, incomplete {n_inc}")


if __name__ == "__main__":
    main()
