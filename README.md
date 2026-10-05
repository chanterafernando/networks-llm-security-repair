# Measuring False Assurance in LLM-Based Automated Vulnerability Repair

Experimento que mide si un LLM es confiable cuando dice haber reparado una vulnerabilidad real de Python.
El LLM (OpenAI API, vía HTTPS desde AWS EC2) propone **un único parche** por caso. Ese parche se **congela** y luego
se verifica de forma independiente con **Vul4Py** (tests funcionales + test de exploit). Al final se calculan
**VRR** (Verified Repair Rate) y **FAR** (False Assurance Rate).

> Lo que dice un LLM sobre su propia reparación es una predicción, no una prueba.

## Estructura

```
networks-llm-security-repair/
├── config.py          # modelo, rutas, prompt obligatorio, esquema JSON, columnas del CSV
├── select_cases.py    # prepara un subconjunto de Vul4Py, corre el scan y elige 5 casos OK
├── repair.py          # código vulnerable -> OpenAI API -> claim + confidence + patch.diff -> CONGELA
├── verify.py          # verifica integridad, corre el evaluador de Vul4Py y Semgrep antes/después
├── metrics.py         # genera results/results.csv, VRR y FAR
├── netprobe.py        # (opcional) mide DNS, TCP, TLS y HTTP por separado
├── run_all.sh         # ejecuta todo el pipeline
├── requirements.txt
├── results/
│   ├── cases.txt              # casos usados
│   ├── case_status.md         # estado de cada candidato (OK / errores)
│   ├── results.csv            # una fila por experimento
│   ├── metrics.txt / .json    # VRR, FAR, latencias
│   ├── network_probe.json
│   └── cases/<VULN_ID>/       # prompt.txt, llm_response.json, patch.diff, freeze.json, eval.json, semgrep_*.json
└── vul4py/                    # clon de https://github.com/tabudz/vul4py (no se versiona)
```

## Instalación (en EC2)

```bash
git clone https://github.com/<usuario>/networks-llm-security-repair.git
cd networks-llm-security-repair
python3 -m venv venv && source venv/bin/activate
python3 -m pip install --upgrade pip
pip install -r requirements.txt
git clone https://github.com/tabudz/vul4py.git

export OPENAI_API_KEY="..."      # nunca en el código ni en GitHub
export OPENAI_MODEL="..."        # identificador exacto del modelo indicado por el instructor
export STUDENT_ID="..."
```

## Ejecución

```bash
# 0) Preparar y escoger casos (solo los que el scan de Vul4Py marca como OK)
python3 select_cases.py --candidates 10          # o: --ids ID1,ID2,ID3,ID4,ID5 si te los asignan

# 1) Una sola reparación por caso + congelamiento
python3 repair.py

# 2) Verificación independiente (Vul4Py) + Semgrep
python3 verify.py

# 3) results.csv + VRR + FAR
python3 metrics.py

# o todo junto:
./run_all.sh
```

## Cómo se usa la OpenAI API

`repair.py` lee los archivos de código relevantes de `vul4py/workspaces/<id>/vulnerable/` (los indicados en
`meta.json → new_code_files`, la misma localización que usa el baseline de Vul4Py) y arma el input:
**el prompt obligatorio, sin modificaciones**, seguido del código fuente. Nunca lee `fixed/`, ni resultados de tests,
ni Semgrep.

La llamada usa `client.responses.create(...)` con **Structured Outputs** (`text.format = json_schema`), para que la
respuesta sea siempre un JSON con `claimed_success`, `confidence` y `patch`. Así se respeta el texto del prompt y
el parseo es fiable.

Se mide la **latencia de la API de extremo a extremo** con `time.perf_counter()` justo antes y después de la petición.
También se guardan el código HTTP, el `x-request-id` y el header `openai-processing-ms` (tiempo de procesamiento
en el servidor), lo que permite separar aproximadamente el tiempo de red del tiempo de inferencia.

Manejo de errores (`error_type` en el CSV):

| error_type | Significado |
|---|---|
| `dns_error` | no se pudo resolver `api.openai.com` (getaddrinfo falló) |
| `connection_error` | fallo TCP/TLS o red |
| `timeout` | no llegó respuesta dentro de `API_TIMEOUT_S` |
| `http_401` | API key inválida o ausente |
| `http_429` | límite de peticiones o de cuota |
| `http_5xx` | error del lado del servidor |
| `parse_error` | el modelo respondió, pero sin JSON válido |

Solo ante fallos de transporte (sin respuesta del modelo: DNS, conexión, timeout, 429, 5xx) se reintenta hasta 2 veces
con backoff exponencial. Eso **no** es un nuevo intento de reparación, porque el modelo nunca llegó a responder.

## Congelamiento

Cuando llega la respuesta se guardan `prompt.txt`, `llm_response.json` y `patch.diff` en
`vul4py/runs/student/<id>/`, se calcula su SHA-256 en `freeze.json` y se ponen en solo lectura (0444).
`repair.py` nunca vuelve a llamar al LLM para un caso ya congelado, y `verify.py` comprueba los hashes antes de evaluar:
si algo cambió, aborta. La única transformación del parche es mecánica y está documentada: quitar fences ```` ``` ````
y añadir el salto de línea final que exige `git apply` (el texto original queda en `llm_response.json → patch_raw`).

## Cómo verifica Vul4Py

`verify.py` llama al evaluador oficial `python3 scripts/evaluate.py --agent student --vuln-id <id>`, que:

1. copia `vulnerable/` a un directorio candidato y aplica `patch.diff` (`git apply`, y si falla `patch -p1`) → `apply_ok`;
2. corre los tests funcionales base → `functional_rc` (0 = pasan; 999 = el proyecto no tiene tests base y Vul4Py lo acepta);
3. corre los tests de exploit/regresión del fix → `exploit_rc` (0 = el exploit ya no funciona);
4. escribe `eval.json`.

Definiciones en `metrics.py`:

```python
verified_repair = patch_applied and functional_test_pass and security_test_pass
false_assurance = claimed_success and not verified_repair
VRR = sum(V) / N
FAR = sum(FA) / sum(C)      # "undefined (no positive repair claims)" si sum(C) == 0
```

`N` = casos con una respuesta congelada y evaluada. Los casos donde la API falló sin respuesta aparecen en el CSV con
`api_success=false`, pero no entran en VRR/FAR. Semgrep (antes/después, sobre los mismos archivos) es solo una medida
secundaria: cero hallazgos **no** prueba que la vulnerabilidad se haya reparado.

## Resultados preliminares

> Completar con el contenido de `results/metrics.txt` después de correr el pipeline. No inventar valores.

```
Cases evaluated (N):
LLM claimed success:
Verified repairs:
False assurances:
VRR:
FAR:
```

Estado de los casos: ver `results/case_status.md`.

## Qué pasa en la red durante la llamada

```
repair.py ──DNS──> api.openai.com → IP(s)            (UDP/TCP 53; si falla: dns_error)
          ──TCP──> SYN / SYN-ACK / ACK con IP:443     (conexión fiable y ordenada)
          ──TLS──> handshake: certificado, SNI, claves (cifrado + autenticidad del servidor)
          ──HTTPS─> POST /v1/responses  (JSON, header Authorization: Bearer <key>)
          <─HTTPS── 200 OK + JSON  (o 401 / 429 / 5xx)
```

- **DNS** traduce el nombre `api.openai.com` a direcciones IP; sin IP no se puede abrir el socket TCP.
- **TCP** da un canal fiable y ordenado (retransmisiones, control de flujo y de congestión).
- **TLS** cifra y autentica: por eso Wireshark ve IPs, puertos y el handshake (incluido el SNI), pero no el código
  ni la API key dentro del POST.
- **HTTPS** = HTTP sobre TLS, puerto **443**. La respuesta trae un **código de estado** (200 OK, 401 no autorizado,
  429 demasiadas peticiones, 5xx error del servidor).
- **JSON** es un formato de texto estructurado, independiente del lenguaje, fácil de generar y parsear: por eso lo
  usan las APIs.
- La **latencia** varía por la congestión de la red, la carga del servidor, la cola de inferencia y sobre todo el
  número de tokens generados (un parche más largo tarda más).

`python3 netprobe.py` descompone estas etapas y guarda en `results/network_probe.json` los tiempos de DNS, TCP y TLS,
la versión de TLS, el certificado y el código HTTP que se obtiene sin API key (401).

## Seguridad y ética

Experimento defensivo: solo usa el benchmark Vul4Py en EC2; no se despliegan aplicaciones vulnerables ni se ataca a
sistemas externos. La API key solo vive en una variable de entorno y `.env` está en `.gitignore`.
