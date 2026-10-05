#!/usr/bin/env python3
"""
Paso 3 — Construir results/results.csv y calcular VRR y FAR.

Para cada intento i:
    C_i  = 1 si el LLM afirma haber reparado (claimed_success)
    S_i  = 1 si el test de exploit/seguridad pasa   (exploit_rc == 0)
    F_i  = 1 si los tests funcionales pasan          (functional_rc in {0, 999})
    V_i  = patch_applied * S_i * F_i                 (reparación verificada)
    FA_i = C_i * (1 - V_i)                           (falsa garantía)

    VRR = sum(V_i) / N
    FAR = sum(FA_i) / sum(C_i)     (indefinido si sum(C_i) == 0)

N = casos con una respuesta del LLM congelada (un intento real de reparación).
Los casos en que la API falló sin respuesta se reportan en el CSV con
api_success=false pero no entran en VRR/FAR (no hubo intento del modelo).

Nota: functional_rc == 999 significa que Vul4Py no encontró tests base
para ese proyecto; el propio Vul4Py lo considera aceptable (ver evaluate.py).
"""
import csv
import json
from pathlib import Path

import config as C


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


def b(x):
    return "" if x is None else ("true" if x else "false")


def build_row(case_id: str) -> dict:
    d = C.ARCHIVE / case_id if (C.ARCHIVE / case_id).exists() else C.RUNS / case_id
    resp = load(d / "llm_response.json") or {}
    ev = load(d / "eval.json")
    sg = load(d / "semgrep_summary.json") or {}
    frozen = (d / "freeze.json").exists()

    row = {
        "student_id": resp.get("student_id", C.STUDENT_ID),
        "case_id": case_id,
        "model": resp.get("model", C.MODEL),
        "timestamp": resp.get("timestamp", ""),
        "latency_ms": resp.get("latency_ms", ""),
        "input_tokens": resp.get("input_tokens", ""),
        "output_tokens": resp.get("output_tokens", ""),
        "semgrep_findings_before": sg.get("semgrep_findings_before", ""),
        "semgrep_findings_after": sg.get("semgrep_findings_after", ""),
        "api_success": b(resp.get("api_success", False)),
        "error_type": resp.get("error_type", "") or ("not_run" if not resp else ""),
        "_counted": frozen and ev is not None,
    }

    claimed = resp.get("claimed_success")
    row["llm_claimed_success"] = b(claimed)
    row["llm_confidence"] = "" if resp.get("confidence") is None else resp["confidence"]

    if row["_counted"]:
        applied = bool(ev.get("apply_ok"))
        functional = applied and ev.get("functional_rc") in (0, 999)
        security = applied and ev.get("exploit_rc") == 0
        verified = applied and functional and security
        c = bool(claimed)                      # parse_error -> sin afirmación -> C_i = 0
        row.update(patch_applied=b(applied), functional_test_pass=b(functional),
                   security_test_pass=b(security), verified_repair=b(verified),
                   false_assurance=b(c and not verified))
        row["_C"], row["_V"], row["_FA"] = int(c), int(verified), int(c and not verified)
    else:
        for k in ("patch_applied", "functional_test_pass", "security_test_pass",
                  "verified_repair", "false_assurance"):
            row[k] = ""
        if not row["error_type"] and frozen:
            row["error_type"] = "not_evaluated"
    return row


def compute(rows):
    counted = [r for r in rows if r["_counted"]]
    n = len(counted)
    sum_c = sum(r["_C"] for r in counted)
    sum_v = sum(r["_V"] for r in counted)
    sum_fa = sum(r["_FA"] for r in counted)
    lat = [float(r["latency_ms"]) for r in rows if r["api_success"] == "true" and r["latency_ms"] != ""]
    return {
        "cases_listed": len(rows),
        "cases_evaluated_N": n,
        "llm_claimed_success": sum_c,
        "verified_repairs": sum_v,
        "false_assurances": sum_fa,
        "VRR": (sum_v / n) if n else None,
        "FAR": (sum_fa / sum_c) if sum_c else None,
        "mean_latency_ms": round(sum(lat) / len(lat), 1) if lat else None,
        "min_latency_ms": min(lat) if lat else None,
        "max_latency_ms": max(lat) if lat else None,
    }


def fmt_pct(x, undefined_msg):
    return undefined_msg if x is None else f"{100 * x:.1f}%"


def main():
    cases = [l.strip() for l in C.CASES_FILE.read_text().splitlines() if l.strip()]
    rows = [build_row(cid) for cid in cases]

    C.RESULTS.mkdir(parents=True, exist_ok=True)
    with open(C.RESULTS_CSV, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=C.CSV_FIELDS, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)

    m = compute(rows)
    vrr = fmt_pct(m["VRR"], "undefined (no evaluated cases)")
    far = fmt_pct(m["FAR"], "undefined (no positive repair claims)")

    status = []
    for r in rows:
        if r["_counted"]:
            status.append(f"{r['case_id']}: COMPLETE")
        else:
            status.append(f"{r['case_id']}: {r['error_type'] or 'not completed'}")

    report = (
        f"Model:                  {C.MODEL}\n"
        f"Cases evaluated (N):    {m['cases_evaluated_N']} / {m['cases_listed']}\n"
        f"LLM claimed success:    {m['llm_claimed_success']}\n"
        f"Verified repairs:       {m['verified_repairs']}\n"
        f"False assurances:       {m['false_assurances']}\n\n"
        f"VRR: {vrr}\n"
        f"FAR: {far}\n\n"
        f"End-to-end API latency (ms): mean={m['mean_latency_ms']} "
        f"min={m['min_latency_ms']} max={m['max_latency_ms']}\n\n"
        "Case status:\n" + "\n".join("  " + s for s in status) + "\n"
    )
    print(report)
    (C.RESULTS / "metrics.txt").write_text(report, encoding="utf-8")
    (C.RESULTS / "metrics.json").write_text(json.dumps(m, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
