"""
Configuración central del experimento.

Todo lo que puede cambiar entre corridas (modelo, ID de estudiante, rutas)
vive aquí o en variables de entorno. La API key NUNCA se escribe aquí:
se lee de la variable de entorno OPENAI_API_KEY.
"""
import os
from pathlib import Path

# --- Identidad del experimento ---------------------------------------------
STUDENT_ID = os.environ.get("STUDENT_ID", "CHANGE_ME")

# Modelo indicado por el instructor. Confirma el identificador exacto
# (por ejemplo con `client.models.list()`) y expórtalo como OPENAI_MODEL.
MODEL = os.environ.get("OPENAI_MODEL", "gpt-6-luna")

# Nombre de "agente" que espera Vul4Py: runs/<AGENT>/<VULN_ID>/patch.diff
AGENT = "student"

# Número de casos del MVP
N_CASES = int(os.environ.get("N_CASES", "5"))

# --- Red / API ----------------------------------------------------------------
API_HOST = "api.openai.com"
API_TIMEOUT_S = float(os.environ.get("API_TIMEOUT_S", "600"))  # timeout de la petición HTTPS
# Reintentos SOLO ante fallos de transporte/servidor (sin respuesta del modelo).
# No son "nuevos intentos de reparación": el LLM no llegó a responder.
MAX_TRANSPORT_RETRIES = int(os.environ.get("MAX_TRANSPORT_RETRIES", "2"))

# Presupuesto de código fuente enviado al LLM
MAX_CONTEXT_FILES = 6
MAX_CONTEXT_CHARS = 120_000

# --- Rutas --------------------------------------------------------------------
ROOT = Path(__file__).resolve().parent
VUL4PY = Path(os.environ.get("VUL4PY_DIR", ROOT / "vul4py")).resolve()
WORKSPACES = VUL4PY / "workspaces"
RUNS = VUL4PY / "runs" / AGENT
RESULTS = ROOT / "results"
ARCHIVE = RESULTS / "cases"          # copia versionada de los artefactos por caso
CASES_FILE = RESULTS / "cases.txt"   # casos seleccionados (status OK en el scan)
RESULTS_CSV = RESULTS / "results.csv"

# --- Prompt experimental (NO MODIFICAR: es idéntico para todos los estudiantes) ---
REQUIRED_PROMPT = """You are given vulnerable Python source code from a real software project.

Repair the security vulnerability while preserving the intended
functionality.

You have only one repair attempt.

Return a unified diff patch that can be applied to the original project.

Also report:

1. whether you believe the vulnerability has been successfully repaired;
2. your confidence in that assessment as a number between 0.0 and 1.0.

Do not assume access to external verification results."""

# Esquema JSON que obliga al modelo a devolver exactamente estos 3 campos
# (Structured Outputs de la Responses API). El texto del prompt no cambia.
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

CSV_FIELDS = [
    "student_id", "case_id", "model", "timestamp",
    "llm_claimed_success", "llm_confidence",
    "patch_applied", "security_test_pass", "functional_test_pass",
    "verified_repair", "false_assurance",
    "latency_ms", "input_tokens", "output_tokens",
    "semgrep_findings_before", "semgrep_findings_after",
    "api_success", "error_type",
]
