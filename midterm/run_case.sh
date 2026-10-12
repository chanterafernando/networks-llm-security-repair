#!/usr/bin/env bash
# Uso: ./run_case.sh CVE-XXXX-YYYY [--scan-only]
set -euo pipefail
ID="${1:?Uso: ./run_case.sh CVE-XXXX-YYYY [--scan-only]}"
cd "$(dirname "$0")"
: "${PIP_CONSTRAINT:?Falta export PIP_CONSTRAINT}"

[ -f "workspaces/$ID/meta.json" ] || { echo "[!] $ID no está descargado"; exit 1; }

echo "=== 1) Scan en vivo de $ID (valida el oráculo) ==="
python scripts/vul4py.py --workspace-root workspaces scan --jobs 1 --only "$ID"
STATUS=$(awk -F'\t' -v id="$ID" '$1==id {print $2}' workspaces/scan_report.tsv)
echo "Estado: $STATUS"
[ "$STATUS" = "OK" ] || { echo "[!] $ID no es OK: oráculo no confiable, no se usa para VRR/FAR."; exit 1; }

echo "=== 2) Restaurar vulnerable/ (el scan deja los tests del exploit adentro) ==="
git -C "workspaces/$ID/vulnerable" checkout HEAD -- .
git -C "workspaces/$ID/vulnerable" clean -fdx -e .venv -e backported_support -e backported_tests
git -C "workspaces/$ID/vulnerable" status --short

if [ "${2:-}" = "--scan-only" ]; then echo "[*] Solo scan (sin OpenAI)."; exit 0; fi
: "${OPENAI_API_KEY:?Falta export OPENAI_API_KEY}"

echo "=== 3) Generar: 1 intento con OpenAI, se congela ==="
python scripts/run_agent.py --agent gpt --model gpt-6-luna --vuln-id "$ID" --runs runs/midterm
echo "=== 4) Verificar con Vul4Py ==="
python scripts/evaluate.py  --agent gpt --vuln-id "$ID" --runs runs/midterm
echo "=== 5) VRR y FAR ==="
python scripts/aggregate_results.py --midterm --runs runs/midterm --agent gpt
