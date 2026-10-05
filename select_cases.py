#!/usr/bin/env python3
"""
Paso 0 — Preparar y seleccionar casos válidos de Vul4Py.

1. Crea un CSV con un subconjunto de casos (para no preparar los 100).
2. Ejecuta vul4py/scripts/prepare.py solo sobre ese subconjunto.
3. Ejecuta el `scan` de Vul4Py solo sobre esos casos.
4. Lee workspaces/scan_report.tsv y se queda con los primeros N casos `OK`.
5. Escribe results/cases.txt y results/case_status.md (documenta los no-OK).

Uso:
    python3 select_cases.py                       # primeros 10 del dataset
    python3 select_cases.py --candidates 15
    python3 select_cases.py --ids CVE-2017-16615,CVE-2018-7753,...
    python3 select_cases.py --skip-prepare --skip-scan   # solo re-leer el reporte
"""
import argparse
import csv
import subprocess
import sys

import config as C


def run(cmd):
    print("$", " ".join(cmd), flush=True)
    return subprocess.run(cmd, cwd=C.VUL4PY).returncode


def read_scan_report():
    path = C.WORKSPACES / "scan_report.tsv"
    if not path.exists():
        sys.exit(f"[!] No existe {path}. Ejecuta el scan primero.")
    with open(path, encoding="utf-8") as f:
        return {r["cve_id"]: r for r in csv.DictReader(f, delimiter="\t")}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ids", default="", help="IDs separados por coma (casos asignados)")
    ap.add_argument("--candidates", type=int, default=10, help="cuántos casos preparar si no se dan --ids")
    ap.add_argument("--n", type=int, default=C.N_CASES, help="cuántos casos OK usar")
    ap.add_argument("--jobs", type=int, default=2)
    ap.add_argument("--skip-prepare", action="store_true")
    ap.add_argument("--skip-scan", action="store_true")
    args = ap.parse_args()

    if not (C.VUL4PY / "scripts" / "prepare.py").exists():
        sys.exit(f"[!] No encuentro Vul4Py en {C.VUL4PY}. Clónalo: git clone https://github.com/tabudz/vul4py.git")

    with open(C.VUL4PY / "dataset" / "vul4py.csv", newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    by_id = {r["vuln_id"]: r for r in rows}

    if args.ids:
        ids = [s.strip() for s in args.ids.split(",") if s.strip()]
        missing = [i for i in ids if i not in by_id]
        if missing:
            sys.exit(f"[!] IDs no presentes en dataset/vul4py.csv: {missing}")
    else:
        ids = [r["vuln_id"] for r in rows[: args.candidates]]
    print(f"[+] Candidatos: {ids}")

    if not args.skip_prepare:
        subset = C.VUL4PY / "dataset" / "student_subset.csv"
        with open(subset, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=["vuln_id", "repo_url", "fix_commit"])
            w.writeheader()
            for i in ids:
                w.writerow({k: by_id[i][k] for k in ("vuln_id", "repo_url", "fix_commit")})
        run([sys.executable, "scripts/prepare.py", "--csv", str(subset), "--jobs", str(args.jobs)])

    if not args.skip_scan:
        run([sys.executable, "scripts/vul4py.py", "--workspace-root", "workspaces",
             "scan", "--jobs", str(args.jobs), "--only", ",".join(ids)])

    report = read_scan_report()
    ok, status_lines = [], []
    for i in ids:
        st = report.get(i, {}).get("status", "NOT_SCANNED")
        if st == "OK" and len(ok) < args.n:
            ok.append(i)
            status_lines.append(f"- {i}: OK (seleccionado)")
        elif st == "OK":
            status_lines.append(f"- {i}: OK (no necesario, ya hay {args.n})")
        else:
            status_lines.append(f"- {i}: {st} — excluido del cálculo de VRR/FAR")

    C.RESULTS.mkdir(parents=True, exist_ok=True)
    C.CASES_FILE.write_text("\n".join(ok) + "\n", encoding="utf-8")
    (C.RESULTS / "case_status.md").write_text(
        "# Estado de los casos Vul4Py\n\n" + "\n".join(status_lines) + "\n", encoding="utf-8")

    print("\n".join(status_lines))
    print(f"[+] {len(ok)} casos OK escritos en {C.CASES_FILE}")
    if len(ok) < args.n:
        print(f"[!] Solo {len(ok)}/{args.n} casos OK. Prueba con --candidates mayor.")


if __name__ == "__main__":
    main()
