# Next-Gen DevSecOps Automation Engine

A FastAPI service that scans Python source for security and structural defects
using **deterministic** analysis (AST + signature/pattern rules), then drafts and
**verifies** remediation patches — re-scanning each patch to prove whether it
actually resolves the finding before saying so.

Detection never involves a language model. A model is optional and is used only
to *draft* a candidate patch; every patch — model-drafted or template — is parsed
and re-scanned by the same deterministic engine, and the result carries an
honest verdict (`validated` / `unresolved` / `rejected` / `not_checked`).

> This is a portfolio / learning project. It is not a replacement for
> `bandit`, `semgrep`, or CodeQL — see [Known limitations](#known-limitations)
> and [`SECURITY.md`](SECURITY.md).

[![CI](https://github.com/Veershah027/next-gen-devsecops-automation-engine/actions/workflows/ci.yml/badge.svg)](https://github.com/Veershah027/next-gen-devsecops-automation-engine/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.11%20|%203.12%20|%203.13-blue)
![Coverage](https://img.shields.io/badge/coverage-92%25-brightgreen)
![License](https://img.shields.io/badge/license-MIT-green)

---

## Architecture

```mermaid
flowchart TD
    A["POST /api/v1/analyze"] --> ORCH
    W["POST /api/v1/webhook<br/>(HMAC + SSRF-safe fetch)"] --> ORCH

    subgraph ORCH["PipelineOrchestrator — asyncio.Semaphore back-pressure"]
      direction TB
      W1["wave 1 — asyncio.gather"]
      W1 --> AST["AST Structural Agent<br/>ast.parse (never executed)"]
      W1 --> SEC["Security Pattern Agent<br/>signatures + 14 rules + entropy"]
      AST --> W2["wave 2 — Remediation Agent"]
      SEC --> W2
      W2 --> VER["verify_patch()<br/>parse → re-scan → verdict"]
    end

    W2 -.->|secret-masked context| LLM["LLM client (optional)<br/>Anthropic / OpenAI → template fallback"]
    LLM -.-> W2
    ORCH --> RESP["AnalyzeResponse<br/>findings + verified patches + metrics"]
    RESP --> DB[("SQLite history<br/>(optional)")]
    ORCH ==>|every log line| BUS["LogBus (pub/sub)"]
    BUS ==> SSE["GET /api/v1/stream-logs<br/>SSE, many consumers"]
```

Module layout mirrors the diagram — see [Project structure](#project-structure).

## Features

- **Deterministic AST analysis** — syntax errors, `O(nᵏ)` nested loops,
  `eval`/`exec`/`compile`/`__import__`, bare `except:`, mutable default args.
- **Deterministic security scanner** — secret signatures + Shannon-entropy +
  14 pattern rules (command injection, path traversal, insecure deserialization,
  weak crypto, weak password hashing, SSRF, TLS-off, JWT misconfig, debug server,
  …), each with false-positive suppression.
- **Verified remediation** — `FINDING → PATCH → VALIDATE → RE-SCAN → VERDICT`.
  Patches are never claimed as "fixed" without a re-scan proving it.
- **Unified diffs** — every snippet patch ships `original_snippet`,
  `suggested_code`, and a `unified_diff`.
- **Optional AI drafting** — provider-agnostic (`anthropic` / `openai`), raw
  HTTP, secret-masked prompts, prompt-injection-aware system prompt, graceful
  fallback to reviewed templates.
- **GitHub webhook** — HMAC-verified `push` / `pull_request`, SSRF-pinned file
  fetching, background processing, `202` + pollable results.
- **Live SSE telemetry** — multi-consumer `LogBus` fan-out with per-subscriber
  back-pressure.
- **Optional SQLite history** — `/api/v1/analyses[...]`; the core pipeline works
  without it.
- **Single-file workspace UI** — calm AI-assistant-style interface, no build
  step; conversational analysis thread, finding cards, code viewer
  (flagged / suggested / diff), verified-remediation flow, dashboard, history,
  light &amp; dark themes.
- **Hardened container** — multi-stage, non-root, read-only FS, dropped caps.
- **Quality gates** — ruff, mypy, 216 tests, 92% coverage, `pip-audit`, all in CI.

## Technology stack

| Concern | Choice |
|---|---|
| Web framework | FastAPI + Starlette (ASGI, `async`/`await` throughout) |
| Validation / config | Pydantic v2 + pydantic-settings (12-factor) |
| HTTP client | httpx (LLM + GitHub) — no vendor SDKs |
| SSE | sse-starlette |
| Persistence | stdlib `sqlite3` (optional, off by default) |
| Analysis | stdlib `ast` + `re` |
| Tooling | ruff, mypy, pytest, pytest-asyncio, coverage, pip-audit |
| Container | python:3.13-slim multi-stage (alpine variant provided) |

## How it works

1. **Ingest & validate.** `AnalyzeRequest` (Pydantic, `extra="forbid"`) then a
   second pass: ≤ 512 KiB, UTF-8, no NUL, Python only, filename reduced to a safe
   basename.
2. **Wave 1 (concurrent).** The AST agent and the security agent run in threads
   via `asyncio.gather`. Neither can crash the pipeline — a failure is captured
   as `AgentReport(status="failed")`.
3. **Wave 2.** The remediation agent takes one representative finding per
   category, drafts a patch (LLM or template), and verifies it.
4. **Assemble.** Findings sorted by severity, metrics computed, `gate_passed`
   set (fails on any HIGH+), response returned — and persisted if enabled.
5. **Telemetry.** Every step emits a line to the `LogBus`, streamed live to any
   number of `/api/v1/stream-logs` clients.

## Security architecture

Full detail in [`SECURITY.md`](SECURITY.md). Highlights:

- Submitted code is **parsed, never executed**.
- Webhook auth: constant-time HMAC-SHA256; missing secret **disables** the
  endpoint (fails closed).
- SSRF: outbound URLs built server-side from verified data, host allow-list,
  `follow_redirects=False`, streamed byte cap.
- Secret masking before any LLM egress.
- Request-body limits, security headers, structured logs with request IDs,
  `/docs` off in production.
- Container: non-root, read-only root FS, `cap_drop: ALL`, `no-new-privileges`.

## Scanner capabilities

| Agent | Technique | Detects |
|---|---|---|
| AST Structural | `ast.parse` + tree walk | `SyntaxError`, 3+ level nested loops, `eval`/`exec`/`compile`/`__import__`, bare `except:`, mutable default args |
| Security Pattern | regex signatures + entropy + rule table | AWS keys, GitHub/Slack/Google tokens, PEM keys, DB URLs with creds, high-entropy literals, string-built SQL, `subprocess(shell=True)`, `os.system`, `pickle.loads`, `yaml.load`, MD5/SHA-1, fast password hashing, `random` for secrets, `verify=False`, `http://` URLs, request-controlled file paths, SSRF-shaped requests, JWT `alg=none` / `verify=False`, debug server enabled |

Every rule carries a category, severity, title, explanation, source location,
remediation hint, and has a positive **and** a negative (false-positive) test.

## AI remediation flow

```
finding ──► build context window ──► mask secrets ──► LLM.complete()
                                                          │
                                          strip fences · bound length
                                                          │
                                                     verify_patch()
                                              ┌───────────┴───────────┐
                                        validated / unresolved     rejected
                                              │                        │
                                         return LLM patch     fall back to template
                                                                       │
                                                                  verify_patch()
```

With no key configured, the flow starts at "fall back to template" — and the
templates are real, self-contained snippets that pass the re-scan, so the
verification story works out of the box.

## Patch verification flow

`verification.verify_patch()`:

1. Reject empty / truncated output (ellipsis markers, unbalanced brackets,
   dangling operators, at the length cap).
2. `ast.parse` the patch — reject if it does not compile.
3. Re-run the relevant scanner (pattern rules and/or AST) against the patch.
4. `finding_resolved = finding.category not in residual_categories`.
5. Verdict: `validated`, `unresolved`, `rejected`, or `not_checked` (guidance
   patches like the SYNTAX template).

## GitHub webhook flow

```
POST /api/v1/webhook
  X-Hub-Signature-256: sha256=<hmac>
  X-GitHub-Event: push | pull_request | ping
```

Constant-time HMAC verify → parse metadata → resolve changed `.py` files
(`push`: from the payload; `pull_request`: from the PR files API) → fetch each
from a **pinned GitHub host** (no redirects, streamed byte cap) → run the
pipeline per file → return `202` immediately. Poll `GET /api/v1/webhook/deliveries`
or watch `GET /api/v1/stream-logs`.

## API endpoints

| Method | Path | Purpose | Codes |
|---|---|---|---|
| `GET` | `/health` | liveness + capability report | `200` |
| `POST` | `/api/v1/analyze` | run the pipeline over one payload | `200`, `422`, `503`, `504` |
| `GET` | `/api/v1/stream-logs` | SSE telemetry, multi-consumer | `200` |
| `GET` | `/api/v1/analyses` | recent analyses (needs persistence) | `200` |
| `GET` | `/api/v1/analyses/{id}` | one analysis summary | `200`, `404` |
| `GET` | `/api/v1/analyses/{id}/report` | full stored report | `200`, `404` |
| `POST` | `/api/v1/webhook` | HMAC-verified GitHub trigger | `202`, `400`, `401`, `503` |
| `GET` | `/api/v1/webhook/deliveries` | recent webhook results | `200` |
| `GET` | `/dashboard` | bundled operator UI | `200` |
| `GET` | `/docs` | Swagger UI (disabled in production) | `200` / `404` |

`POST /api/v1/analyze` response (abridged):

```jsonc
{
  "analysis_id": "…",
  "gate_passed": false,
  "remediation_mode": "template",          // llm | template | mixed | none
  "stored": false,
  "metrics": { "total_findings": 8, "highest_severity": "critical", "by_severity": {…} },
  "agent_reports": [ { "agent": "security_pattern_scanner", "status": "completed", "duration_ms": 3.1 } ],
  "findings": [ { "id": "…", "category": "sql_injection", "severity": "critical", "position": {"line": 34} } ],
  "patches": [ {
    "category": "sql_injection",
    "patch_type": "snippet",
    "source": "template",
    "original_snippet": "…", "suggested_code": "…", "unified_diff": "--- …",
    "validation": { "status": "validated", "parsed_ok": true, "finding_resolved": true }
  } ]
}
```

## Workspace UI

A single self-contained HTML file — Tailwind + Inter/JetBrains Mono via CDN,
vanilla JS, **no build step**. Calm, minimalist, keyboard-friendly, light and
dark themes.

**How to open it:** start the engine, then browse to `/dashboard` **on the port
the engine is actually listening on** — e.g. `http://127.0.0.1:8000/dashboard`.
It's served same-origin, so there's nothing to configure. If port 8000 is
already in use on your machine, run `uvicorn main:app --port 8010` and open
`http://127.0.0.1:8010/dashboard` instead. (Opening `index.html` through a
static server like VS Code Live Server also works — the UI auto-detects the
engine on `:8000`, or you set the API URL in **Settings**.)

- **Analysis thread** — submit code, get a conversational security response;
  multiple submissions form a session thread with live agent telemetry (SSE)
- **Finding cards** — severity, category, location, redacted evidence,
  remediation hint; expandable
- **Code viewer** — flagged snippet (vulnerable line highlighted) · suggested
  patch · unified diff, with lightweight Python syntax highlighting
- **Verified-remediation flow** — a visible `generated → validated → re-scanned
  → resolved` chain and a *Verified remediation* badge only when the backend
  reports `validation.status == "validated"`
- **Dashboard / History / Findings / Remediation** — aggregated from real
  responses (and the SQLite store when persistence is on)
- **Webhooks / Infrastructure / Settings** — live capability + component status
  from `/health`, recent webhook deliveries, API-URL and theme controls
- Error, loading, empty and offline states throughout — nothing fails silently

> Screenshots: _add `docs/dashboard.png` after cloning and running locally._

## Local installation

```bash
git clone https://github.com/Veershah027/next-gen-devsecops-automation-engine.git
cd next-gen-devsecops-automation-engine

python -m venv .venv
.venv\Scripts\activate            # Windows   ·   source .venv/bin/activate elsewhere
pip install -r requirements.txt

cp .env.example .env               # optional — runs fully without it

# pick any free port; 8000 is just the default
uvicorn main:app --reload --port 8000
```

Then open, **on that same port**:

- Workspace UI — `http://127.0.0.1:8000/dashboard`
- API docs — `http://127.0.0.1:8000/docs`

> If `uvicorn` reports `address already in use`, another program owns port 8000 —
> re-run with `--port 8010` (or any free port) and use that number in the URLs
> above.

```bash
PORT=8000   # match the port you started the engine on
curl -s -X POST "http://127.0.0.1:$PORT/api/v1/analyze" \
  -H 'Content-Type: application/json' \
  -d '{"filename":"svc.py","source_code":"import os\nAPI_KEY = \"AKIAIOSFODNN7EXAMPLE\"\n"}' | python -m json.tool
```

## Docker installation

```bash
docker compose up --build
```

- Dashboard — `http://localhost:8080` (the API is reverse-proxied, so it's
  same-origin — nothing to configure)
- Engine (direct) — `http://localhost:8000`

If 8000 / 8080 are taken on your machine, remap the host ports:

```bash
ENGINE_PORT=8100 DASHBOARD_PORT=8180 docker compose up --build
# → dashboard at http://localhost:8180
```

Single container:

```bash
docker build -t devsecops-engine .
docker run --rm -p 8000:8000 -e DEVSECOPS_ENVIRONMENT=production devsecops-engine
# → http://localhost:8000/dashboard   (change the left-hand 8000 if the port is busy)
```

Deploys as-is to AWS ECS / Google Cloud Run: push the image, set the `DEVSECOPS_*`
environment, expose the container's port 8000.

## Environment variables

Every knob is a `DEVSECOPS_`-prefixed variable — full list with defaults in
[`.env.example`](.env.example). The essentials:

| Variable | Default | Purpose |
|---|---|---|
| `DEVSECOPS_ENVIRONMENT` | `development` | `production` disables `/docs` and reload |
| `DEVSECOPS_CORS_ALLOW_ORIGINS` | common dev ports (3000/5173/5500/8080) | exact browser origins (JSON array) — only needed for a cross-origin static-server UI |
| `DEVSECOPS_LLM_PROVIDER` | `null` | `anthropic` / `openai` to enable AI drafting |
| `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` | — | provider key (or `DEVSECOPS_LLM_API_KEY`) |
| `DEVSECOPS_GITHUB_WEBHOOK_SECRET` | — | unset ⇒ `/api/v1/webhook` returns `503` |
| `DEVSECOPS_WEBHOOK_ALLOWED_REPOS` | `[]` | `["owner/repo"]`; `[]` = any HMAC-valid repo |
| `DEVSECOPS_PERSISTENCE_ENABLED` | `false` | enable the SQLite analysis history |

## Testing

```bash
pip install -r requirements-dev.txt

ruff check .            # lint (pycodestyle, pyflakes, bugbear, bandit, isort, …)
ruff format --check .   # formatting
mypy                    # type-check (disallow_untyped_defs on the 6 source modules)
pytest --cov            # 216 tests, ~92% branch coverage, < 2 s
pip-audit -r requirements.txt
```

Test layout:

| File | Covers |
|---|---|
| `test_config.py` | Settings validation (env, GitHub URLs, repo specs, bounds) |
| `test_validation.py` | payload validation, filename sanitisation, path traversal |
| `test_scanner_ast.py` | every AST rule + clean-code negatives |
| `test_scanner_security.py` | every signature + all 14 pattern rules (positive **and** negative) |
| `test_masking.py` | secret masking, structure preservation |
| `test_verification.py` | validate / unresolved / rejected / not_checked paths |
| `test_webhook_security.py` | HMAC, SSRF host allow-list, path safety, plan parsing, endpoint |
| `test_webhook_processing.py` | file fetch + analyse with a mocked GitHub |
| `test_pipeline.py` | waves, gate, metrics, LLM path, fallback, timeout, overload, agent isolation |
| `test_llm_client.py` | Anthropic/OpenAI success, malformed, 4xx, retryable 5xx, timeout, truncation |
| `test_persistence.py` | SQLite round-trip, null store, write-failure isolation |
| `test_api.py` | every endpoint, security headers, body limit, production `/docs` |
| `test_observability.py` | `LogBus` fan-out + back-pressure |

No test makes a real network call.

## CI/CD

[`.github/workflows/ci.yml`](.github/workflows/ci.yml), on push / PR to `main`:

1. `ruff check` + `ruff format --check`
2. `mypy`
3. `pytest` + coverage (`--cov-fail-under=85`) on Python 3.11 / 3.12 / 3.13
4. `pip-audit --strict` (separate job)
5. Docker build → run container → hit `/health` → smoke-test `/api/v1/analyze`
6. Trivy image scan (report-only)

## Security limitations

Stated plainly in [`SECURITY.md` §5](SECURITY.md#5-scanner-limitations-be-honest-with-yourself):
regex + single-file AST, **no dataflow / taint / cross-file analysis**, false
negatives expected, severity is a fixed heuristic, the `gate_passed` policy is a
demo not a compliance control. `/analyze` is unauthenticated by design.

## Known limitations

- No authentication on `/analyze` or the history endpoints — put a gateway in
  front for anything multi-tenant.
- The webhook delivery buffer and (optionally) SQLite are single-instance;
  multi-replica needs Redis / Postgres.
- `main.py` is ~1.5 k lines — the largest module. It is cohesive but a further
  split (agents / middleware / routes) is a reasonable next step.
- LLM patch quality depends entirely on the model; the engine only guarantees
  the *verdict* is honest, not that a `validated` patch is idiomatic.
- Python source only.

## Roadmap

- [ ] Split `main.py` into `agents.py` / `middleware.py` / `routes.py`
- [ ] `bandit` / `semgrep` as an optional third agent
- [ ] AuthN (API key / OAuth2) on `/analyze` and history
- [ ] Postgres persistence option + Alembic
- [ ] SARIF export for GitHub code scanning
- [ ] Per-caller rate limiting

## Project structure

```
.
├── main.py                 # config, logging, LogBus, agents, orchestrator, webhook, HTTP app
├── models.py               # constants, enums, Pydantic schemas, error hierarchy
├── scanner.py              # entropy / masking / HMAC / SSRF guards + signature & rule tables + AST scan
├── verification.py         # patch validation and re-scan
├── persistence.py          # optional SQLite analysis history
├── llm.py                  # provider-agnostic async LLM client (Anthropic / OpenAI / null)
├── index.html              # single-file operator dashboard
├── tests/                  # 216 tests
├── requirements.txt        # pinned runtime deps
├── requirements-dev.txt    # tooling
├── pyproject.toml          # ruff / mypy / pytest / coverage config
├── Dockerfile              # multi-stage slim (Dockerfile.alpine = musl variant)
├── docker-compose.yml      # engine + nginx dashboard, hardened
├── .github/workflows/ci.yml
├── SECURITY.md
└── LICENSE                 # MIT
```

## License

[MIT](LICENSE) © Veer Shah
