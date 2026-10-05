#!/usr/bin/env bash
# Pipeline completo: (selección) -> reparación + congelamiento -> verificación -> métricas
set -euo pipefail
cd "$(dirname "$0")"
: "${OPENAI_API_KEY:?Exporta OPENAI_API_KEY primero}"

[ -s results/cases.txt ] || python3 select_cases.py --candidates "${CANDIDATES:-10}"
python3 netprobe.py || echo "[!] netprobe falló (no bloquea el experimento)"
python3 repair.py        # 1) LLM -> claim + confidence + patch.diff  -> CONGELADO
python3 verify.py        # 2) Vul4Py (funcional + exploit) + Semgrep
python3 metrics.py       # 3) results.csv + VRR + FAR
