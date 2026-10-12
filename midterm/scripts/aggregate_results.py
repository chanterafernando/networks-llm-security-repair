#!/usr/bin/env python3
"""aggregate_results.py

Rebuild a complete eval summary from every runs/<agent>/<vuln_id>/eval.json.

run_eval.py rewrites eval_summary.csv using only the cases processed in that
invocation, so a `--only` resume clobbers the full rollup. The per-case
eval.json files are the durable source of truth; this script reassembles them
into a complete CSV + prints a per-agent rollup and a list of any (agent,case)
pairs still missing an eval.json.

MIDTERM EXTENSION (task 4 of Section 4.3)
-----------------------------------------
With --midterm the script aggregates the attempts found under
runs/<...>/<agent>/ (one directory per repair attempt) instead of every
workspace, and computes the Section 3 metrics:

    VRR = sum(V_i) / N
    FAR = sum(FA_i) / sum(C_i)      (undefined if sum(C_i) == 0)

where N is the number of COMPLETED observations. It
  * keeps every attempt in results.csv, including unsuccessful ones;
  * lists incomplete attempts (verification error, missing tests, timeout,
    API error without a model response, not evaluated) separately and never
    counts them as passes or failures;
  * prints and saves the denominators used (N and sum C_i);
  * reports "FAR = undefined (no positive repair claims)" instead of 0.

Outputs (next to the run directory):
    results.csv    one row per attempt with (C,P,A,F,S,V,FA,L) and metadata
    metrics.json   VRR, FAR, N, sum C, sum V, sum FA, incomplete list
"""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
COLS = ["agent", "vuln_id", "apply_ok", "func_ok", "exploit_ok", "plausible",
        "func_pfes", "exploit_pfes", "elapsed_s", "notes"]

MIDTERM_COLS = [
    "agent", "vuln_id", "model", "timestamp", "status", "incomplete_reason",
    "C_claimed_success", "P_confidence",
    "A_patch_applied", "F_functional_pass", "S_security_pass",
    "V_verified_repair", "FA_false_assurance",
    "L_latency_ms", "input_tokens", "output_tokens",
    "functional_rc", "exploit_rc", "api_error_type",
]


def _load(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None
    except Exception:
        return None


def _blank(x):
    return "" if x is None else x


def midterm(args) -> None:
    agent_dir = args.runs / args.agent
    if not agent_dir.exists():
        raise SystemExit(f"no attempts under {agent_dir}")

    rows, completed, incomplete = [], [], []
    for d in sorted(p for p in agent_dir.iterdir() if p.is_dir()):
        gen = _load(d / "generation.json") or {}
        ev = _load(d / "eval.json")

        if ev is None:
            # No evaluation: either the API never produced a response, or the
            # frozen attempt has not been evaluated yet.
            if not (d / "freeze.json").exists():
                status, reason = "incomplete", f"no_model_response:{gen.get('error_type') or 'unknown'}"
            else:
                status, reason = "incomplete", "not_evaluated"
            ev = {}
        else:
            status = ev.get("status", "incomplete")
            reason = ev.get("incomplete_reason", "")

        row = {
            "agent": args.agent,
            "vuln_id": d.name,
            "model": gen.get("model") or ev.get("model"),
            "timestamp": gen.get("timestamp"),
            "status": status,
            "incomplete_reason": reason,
            "C_claimed_success": ev.get("C", None if gen.get("claimed_success") is None
                                         else int(bool(gen.get("claimed_success")))),
            "P_confidence": ev.get("P", gen.get("confidence")),
            "A_patch_applied": ev.get("A"),
            "F_functional_pass": ev.get("F"),
            "S_security_pass": ev.get("S"),
            "V_verified_repair": ev.get("V"),
            "FA_false_assurance": ev.get("FA"),
            "L_latency_ms": gen.get("latency_ms"),
            "input_tokens": gen.get("input_tokens"),
            "output_tokens": gen.get("output_tokens"),
            "functional_rc": ev.get("functional_rc"),
            "exploit_rc": ev.get("exploit_rc"),
            "api_error_type": gen.get("error_type", ""),
        }
        rows.append(row)

        # A completed observation needs a model claim and a finished verification.
        if status == "complete" and row["V_verified_repair"] is not None:
            # A parse error (model answered without a usable claim) counts as C=0.
            if row["C_claimed_success"] is None:
                row["C_claimed_success"] = 0
                row["FA_false_assurance"] = 0
            completed.append(row)
        else:
            incomplete.append(row)

    n = len(completed)
    sum_c = sum(int(r["C_claimed_success"]) for r in completed)
    sum_v = sum(int(r["V_verified_repair"]) for r in completed)
    sum_fa = sum(int(r["FA_false_assurance"]) for r in completed)
    vrr = (sum_v / n) if n else None
    far = (sum_fa / sum_c) if sum_c else None

    out_dir = args.runs
    out_csv = args.out or (out_dir / "results.csv")
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=MIDTERM_COLS)
        w.writeheader()
        for r in rows:
            w.writerow({k: _blank(r.get(k)) for k in MIDTERM_COLS})

    lat = [r["L_latency_ms"] for r in rows if r["L_latency_ms"] is not None and not r["api_error_type"]]
    metrics = {
        "agent": args.agent,
        "attempts_found": len(rows),
        "completed_N": n,
        "incomplete": [{"vuln_id": r["vuln_id"], "reason": r["incomplete_reason"]} for r in incomplete],
        "sum_C": sum_c,
        "sum_V": sum_v,
        "sum_FA": sum_fa,
        "VRR": vrr,
        "FAR": far,
        "FAR_note": "" if sum_c else "undefined (no positive repair claims)",
        "mean_latency_ms": round(sum(lat) / len(lat), 1) if lat else None,
    }
    (out_dir / "metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")

    # ---- report ----
    print(f"[+] wrote {out_csv}")
    print(f"[+] wrote {out_dir / 'metrics.json'}\n")
    print(f"  {'vuln_id':<18} {'status':<11} C  A  F  S  V  FA  L_ms")
    for r in rows:
        def s(k):
            v = r.get(k)
            return "-" if v is None else str(v)
        print(f"  {r['vuln_id']:<18} {r['status']:<11} {s('C_claimed_success'):<2} {s('A_patch_applied'):<2} "
              f"{s('F_functional_pass'):<2} {s('S_security_pass'):<2} {s('V_verified_repair'):<2} "
              f"{s('FA_false_assurance'):<3} {s('L_latency_ms')}")
    print()
    print(f"  Attempts found:            {len(rows)}")
    print(f"  Completed observations N:  {n}")
    print(f"  Incomplete (excluded):     {len(incomplete)}"
          + (" -> " + ", ".join(f"{r['vuln_id']} ({r['incomplete_reason']})" for r in incomplete)
             if incomplete else ""))
    print(f"  Positive claims sum(C):    {sum_c}")
    print(f"  Verified repairs sum(V):   {sum_v}")
    print(f"  False assurances sum(FA):  {sum_fa}\n")
    print(f"  VRR = {sum_v}/{n} = {100 * vrr:.1f}%" if n else "  VRR = undefined (no completed observations)")
    print(f"  FAR = {sum_fa}/{sum_c} = {100 * far:.1f}%" if sum_c else "  FAR = undefined (no positive repair claims)")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--workspaces", type=Path, default=HERE.parent / "workspaces")
    ap.add_argument("--runs", type=Path, default=HERE.parent / "runs")
    ap.add_argument("--agents", default="claude,gpt,openhands,swe,trae")
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument("--midterm", action="store_true",
                    help="Aggregate the attempts under --runs/--agent and compute VRR/FAR (Section 3)")
    ap.add_argument("--agent", default="gpt", help="Agent to aggregate with --midterm")
    args = ap.parse_args()

    if args.midterm:
        midterm(args)
        return

    agents = [a.strip() for a in args.agents.split(",") if a.strip()]
    cases = sorted(
        d.name for d in args.workspaces.iterdir()
        if d.is_dir() and (d / "meta.json").exists()
    )
    out_csv = args.out or (args.runs / "eval_summary_full.csv")

    rows = []
    missing = []
    for vid in cases:
        for agent in agents:
            ej = args.runs / agent / vid / "eval.json"
            if ej.exists():
                try:
                    rows.append(json.loads(ej.read_text()))
                except Exception as e:
                    missing.append(f"{agent}/{vid} (corrupt: {e})")
            else:
                missing.append(f"{agent}/{vid}")

    with open(out_csv, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=COLS)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in COLS})

    # per-agent rollup
    roll = {}
    for r in rows:
        d = roll.setdefault(r.get("agent", "?"), {"plausible": 0, "applied": 0, "total": 0})
        d["total"] += 1
        if r.get("apply_ok"):
            d["applied"] += 1
        if r.get("plausible"):
            d["plausible"] += 1

    print(f"[+] {len(cases)} cases x {len(agents)} agents = {len(cases)*len(agents)} pairs; "
          f"{len(rows)} evaluated, {len(missing)} missing")
    print(f"[+] wrote {out_csv}\n")
    print(f"  {'agent':<10} {'plausible':>10} {'applied':>9} {'total':>7}  plausible%")
    for a in agents:
        d = roll.get(a, {"plausible": 0, "applied": 0, "total": 0})
        pct = (100.0 * d["plausible"] / d["total"]) if d["total"] else 0.0
        print(f"  {a:<10} {d['plausible']:>10} {d['applied']:>9} {d['total']:>7}  {pct:8.1f}%")

    if missing:
        print(f"\n[!] missing eval.json ({len(missing)}):")
        for m in missing:
            print(f"      {m}")


if __name__ == "__main__":
    main()
