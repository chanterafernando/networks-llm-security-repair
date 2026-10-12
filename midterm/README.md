# Midterm — Measuring False Assurance in LLM-Based Automated Vulnerability Repair

This folder contains my extension of [Vul4Py](https://github.com/tabudz/vul4py) (base commit
`2649d7b89e796738ebc2bc3fa9480dff5ae15898`). It measures whether an LLM can be trusted when it claims
to have repaired a real Python vulnerability, using the **Verified Repair Rate (VRR)** and the
**False Assurance Rate (FAR)**.

```
vulnerable code ──HTTPS──> OpenAI API (gpt-6-luna) ──> claim + confidence + patch.diff
      ──> FROZEN (SHA-256) ──> Vul4Py: patch apply + functional tests + exploit test
      ──> eval.json (A, F, S, V, FA) ──> results.csv + VRR + FAR
```

| File | Assignment task |
|---|---|
| `scripts/run_agent.py` | 1. Capture claim, confidence and patch · 2. Freeze the attempt |
| `scripts/evaluate.py` | 3. Per-attempt indicators A, F, S, V, FA; incomplete-verification handling |
| `scripts/aggregate_results.py` | 4. VRR and FAR with explicit denominators |
| `run_case.sh` | Live scan → restore `vulnerable/` → generate → evaluate → aggregate |
| `vul4py_changes.diff` | Exact changes against the base commit |
| `results/` | Evidence of the evaluated case(s) |

## 1. Installation (AWS EC2, Amazon Linux 2023)

```bash
sudo dnf install -y python3.12 python3.12-pip python3.12-devel \
  git gcc gcc-c++ make libffi-devel openssl-devel patch bzip2 xz
git clone https://github.com/tabudz/vul4py.git && cd vul4py
git checkout 2649d7b89e796738ebc2bc3fa9480dff5ae15898
python3.12 -m venv .venv && source .venv/bin/activate
python -m pip install openai

# copy this folder's scripts over the originals
cp ../midterm/scripts/*.py scripts/ && cp ../midterm/run_case.sh . && chmod +x run_case.sh

# environment fix: recent setuptools no longer ships pkg_resources
echo "setuptools<81" > constraints.txt
export PIP_CONSTRAINT="$PWD/constraints.txt"

python scripts/prepare.py --jobs 2          # downloads vulnerable/ and fixed/ for each case
```

## 2. How to run

```bash
export OPENAI_API_KEY="..."                  # terminal only, never committed
./run_case.sh CVE-2021-32839                 # one case end to end
./run_case.sh CVE-2021-32839 --scan-only     # oracle validation only, no API call
```

Equivalent individual commands:

```bash
python scripts/vul4py.py --workspace-root workspaces scan --jobs 1 --only CVE-2021-32839
python scripts/run_agent.py --agent gpt --model gpt-6-luna --vuln-id CVE-2021-32839 --runs runs/midterm
python scripts/evaluate.py  --agent gpt --vuln-id CVE-2021-32839 --runs runs/midterm
python scripts/aggregate_results.py --midterm --runs runs/midterm --agent gpt
```

Outputs per case in `runs/midterm/gpt/<ID>/`: `prompt.txt`, `response_raw.json`, `llm_response.json`,
`generation.json`, `patch.diff`, `freeze.json`, `eval.json`, `logs/`. Aggregates: `runs/midterm/results.csv`
and `runs/midterm/metrics.json`.

## 3. How the OpenAI API is used

- One request per case to **Chat Completions** with model `gpt-6-luna`.
- **System message:** the fixed experimental prompt (`REPAIR_PROMPT`). **User message:** only the vulnerable
  source files listed in `meta.json → new_code_files`. The fix commit, repository URL, `fixed/`, tests and
  verification results are never sent.
- **Structured Outputs** (strict JSON schema) force the answer to
  `{"claimed_success": bool, "confidence": number, "patch": string}`.
- End-to-end latency is measured with `time.perf_counter()` right before and after the request. Tokens,
  HTTP status, `x-request-id` and `openai-processing-ms` are recorded.
- `max_retries=0`: one attempt only. A response is **frozen** (SHA-256 + read-only) and never regenerated.
  If the API fails before answering (DNS, 401, 429, 5xx, timeout) the error is recorded and nothing is frozen.

## 4. How Vul4Py verifies a patch

1. **Scan** (before calling the model): the oracle is valid (`OK`) only if the functional tests pass on
   `vulnerable/` and `fixed/`, and the exploit test fails on `vulnerable/` and passes on `fixed/`.
2. `evaluate.py` checks the freeze hashes, then **A**: does `patch.diff` apply to the original project?
3. A copy of `vulnerable/` is patched and installed; **F**: do the baseline functional tests pass?
4. The exploit tests from the fix are run on the same patched copy; **S**: do they pass?
5. `V = A·F·S` and `FA = C·(1 − V)`. Missing tests (rc 999), no collected tests, timeouts and setup errors
   are recorded as **incomplete**, never as a pass (the original `plausible` rule accepted rc 999).

```
VRR = ΣV / N          FAR = ΣFA / ΣC   (undefined if ΣC = 0)
```

## 5. Preliminary results

As instructed by the professor, one case was evaluated (N = 1).

| Case | C | P | A | F | S | V | FA | L (ms) |
|---|---|---|---|---|---|---|---|---|
| CVE-2021-32839 | _ | _ | _ | _ | _ | _ | _ | _ |

**VRR = _ · FAR = _** (see `results/metrics.json`).

Case preparation: 98/100 cases downloaded (CVE-2024-47164 and CVE-2024-4941: fix commit unreachable,
`git checkout` exit 128). Scan of the first 30 candidates: 4 OK, 15 UNEXPECTED, 10 INFRA_BROKEN, 1 NON_ORACLE.

## 6. What happens over the network

| Step | What happens | Measured from EC2 |
|---|---|---|
| DNS | `api.openai.com` → A/AAAA records (IP addresses) | 6.6 ms, 2 IPv4 + 2 IPv6 |
| TCP | Three-way handshake to port 443 (reliable, ordered channel) | 1.25 ms |
| TLS | Handshake: certificate, key exchange → encrypted channel | 4.01 ms, TLS 1.3, AES-256-GCM |
| HTTPS | `POST /v1/chat/completions`, JSON body, `Authorization: Bearer` header | 401 without key (expected) |
| Model | Server-side inference, JSON response | ≈ 1.5 s for a minimal call |

Connection setup takes ~12 ms; almost all latency is server processing and inference, so the measured value
is **end-to-end API latency**, not network delay. Because traffic is encrypted, Wireshark only sees IPs,
ports, the SNI hostname, sizes and timing — not the source code or the API key.
Observed errors: **429** `insufficient_quota` (no credits), **401** (invalid key), and a client-side
`Illegal header value` caused by a trailing space in the key (no request ever reached the network).
