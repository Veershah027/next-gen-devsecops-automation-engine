# Security Posture

This document describes what the engine actually does, what it deliberately does
not do, and how to run it safely. It is written to be checked against the code —
if you find a discrepancy, that is a bug in this document.

---

## 1. What this tool is

A **deterministic** static analyser for Python source, plus an **AI-assisted,
self-verifying** remediation layer.

* **Detection is 100% deterministic.** The AST agent uses `ast.parse` + a tree
  walk; the security agent uses a fixed table of regex signatures and pattern
  rules. No model is consulted to decide whether something is a finding.
* **Remediation** drafts a candidate patch. If an LLM provider is configured it
  drafts the patch; otherwise a reviewed template is used. **Either way the patch
  is parsed and re-scanned** before the engine reports whether it resolves the
  finding (`validation.status` ∈ `validated` / `unresolved` / `rejected` /
  `not_checked`).
* Analysed source is **parsed, never executed** — there is no `exec`, `compile`,
  `eval`, `import`, `subprocess`, or `os.system` path that touches user input.

## 2. Secret & sensitive-data hygiene

| Check | Result |
|-------|--------|
| Live cloud / LLM credentials in tracked files | none — all keys come from the environment |
| PII / personal data | none — the service processes code payloads only |
| `.env` committed | no; `.gitignore` blocks `.env`, `.env.*`, `*.pem`, `*.key`, `id_rsa*`, `*.db`, `data/`, `credentials.json`, `service-account*.json` (with `!.env.example`) |
| SQLite database committed | no; `data/` and `*.db` are ignored |

**Intentional non-secret literal:** `AKIAIOSFODNN7EXAMPLE` (and the matching
example secret key) are **AWS's own published documentation values**. They appear
only in the dashboard's pre-loaded sample and in test fixtures, and match no real
account. They exist so the scanner has something to detect in the demo.

## 3. OWASP Top 10 (2021) — controls in code

| # | Category | Control |
|---|----------|---------|
| A01 Broken Access Control | Webhook gated by HMAC-SHA256 (`scanner.verify_github_signature`, `hmac.compare_digest`); optional `DEVSECOPS_WEBHOOK_ALLOWED_REPOS` allow-list; the persistence endpoints expose only analyses the engine itself produced. |
| A02 Cryptographic Failures | Constant-time signature comparison; every upstream URL forced to `https://` and an allow-listed host; TLS verification left at the library default (on). |
| A03 Injection | Submitted Python is parsed, never executed; no shell, no SQL, no template engine on request data; `scanner.sanitize_filename` strips control chars + path separators before any value is logged; logs are structured JSON. |
| A04 Insecure Design | 512 KiB source cap; 2 MiB request-body cap (`BodySizeLimitMiddleware`) + 1 MiB webhook-body cap; `asyncio.Semaphore` back-pressure → `503`; per-agent / per-remediation / per-pipeline `asyncio.wait_for` budgets → `504`; webhook fans out at most `webhook_max_files` files; lines longer than 4 KiB are skipped before regex scanning (ReDoS guard); CPU-bound parsing runs in a worker thread. |
| A05 Security Misconfiguration | `SecurityHeadersMiddleware` (`nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, COOP, `Permissions-Policy`, and `Content-Security-Policy: default-src 'none'` on API paths); `/docs` + `/openapi.json` disabled when `ENVIRONMENT=production`; error bodies include `repr(exc)` only when `DEBUG=true`; container runs non-root, read-only root FS, `cap_drop: ALL`, `no-new-privileges`. |
| A06 Vulnerable Components | Exact-pinned `requirements.txt` (direct + transitive); no vendor SDKs (raw HTTP via `httpx`); multi-stage image so build tooling never ships; `pip-audit` runs in CI. |
| A07 Auth Failures | The webhook is the only authenticated endpoint. Missing/blank secret **disables** it (`503`) rather than failing open. `/analyze` is intentionally unauthenticated (self-service scanner) — front it with your gateway for multi-tenant use. |
| A08 Integrity Failures | Webhook payloads are HMAC-checked **before** `json.loads`; no `pickle`, `yaml.load`, `eval`, or dynamic import of request data anywhere in the engine. |
| A09 Logging & Monitoring | Structured JSON logs with a propagated `X-Request-ID`; every pipeline line mirrored to the process log and the SSE telemetry bus; `/health` reports live capability; webhook deliveries retained (last 50). |
| A10 SSRF | Webhook fetch URLs are **built server-side** from the HMAC-verified `repository`/`sha`, never taken from the payload; every outbound URL passes `scanner.assert_allowed_github_url` (scheme `https`, host ∈ `{api.github.com, raw.githubusercontent.com, github.com, objects.githubusercontent.com, codeload.github.com}`); `httpx` client created with `follow_redirects=False`; responses streamed with a hard byte cap; repo-relative paths normalised and any `..` / absolute / backslash / NUL path rejected. |

## 4. LLM integration — prompt-injection stance

Analysed source is **untrusted data**, and the remediation prompt says so
explicitly. Before any code window leaves the process, `scanner.mask_secrets`
blanks anything credential-shaped (AWS/Slack/GitHub tokens, PEM blocks,
`scheme://user:pass@host` URLs, and any ≥20-char quoted literal) to
`<redacted:N>`. The model is asked for a code snippet only; its output is:

* stripped of markdown fences,
* length-bounded (`MAX_PATCH_CHARS`),
* `ast.parse`d (rejected if it does not compile),
* checked for truncation markers / unbalanced brackets,
* **re-scanned**; if the finding still fires, the patch is `unresolved`, not
  "fixed".

The model has no tool access: it cannot execute code, run shell commands, read
the filesystem, reach credentials, or fetch URLs. Only the one configured
provider host is ever contacted, and only when a key is set. A rejected LLM patch
falls back to the verified template.

## 5. Scanner limitations (be honest with yourself)

* **Regex + single-file AST, not dataflow.** There is no taint tracking, no
  cross-file analysis, no type inference. A vulnerability that only appears when
  data flows across functions or modules will be missed.
* **False negatives are expected.** The pattern rules match common, idiomatic
  shapes of each weakness. Obfuscated or unusual code will slip through. This is
  a first-pass triage aid, not a substitute for `bandit`, `semgrep`, CodeQL, or a
  human reviewer.
* **False positives are possible.** Rules have `# nosec` / `usedforsecurity=False`
  suppression and placeholder-value heuristics, but context-free matching will
  sometimes over-report. Treat findings as leads.
* **Severity is a fixed heuristic**, not a CVSS calculation.
* **The gate** (`gate_passed`) fails on any HIGH+ finding. It is a demo policy,
  not a compliance control.

## 6. Residual risks & recommendations

| Risk | Status | Recommendation |
|------|--------|----------------|
| `/analyze` is unauthenticated | by design | front with an API gateway / OAuth2 / mTLS for shared deployments |
| `ast.parse` on adversarial input | mitigated (size cap + thread + timeout) | keep the 512 KiB cap; for hostile multi-tenant input, parse in a subprocess with `RLIMIT_AS` |
| In-memory webhook delivery buffer | fine for one instance | move to the SQLite store or Redis for multiple replicas |
| SQLite persistence under concurrency | serialised by a lock, single connection | for real load use Postgres; keep persistence optional |
| No per-caller rate limiting | out of scope | enforce at the gateway; the concurrency semaphore is a global ceiling, not fairness |
| LLM prompt-injection via analysed code | low (output is code shown to a human, never executed, always re-scanned) | keep "human review required" on every patch; never auto-apply |

## 7. Deployment checklist

- [ ] `DEVSECOPS_ENVIRONMENT=production`, `DEVSECOPS_DEBUG=false`
- [ ] `DEVSECOPS_CORS_ALLOW_ORIGINS` set to the real dashboard origin(s) only
- [ ] `DEVSECOPS_GITHUB_WEBHOOK_SECRET` = 32+ random bytes, matched in GitHub
- [ ] `DEVSECOPS_WEBHOOK_ALLOWED_REPOS` populated
- [ ] LLM key supplied via a secret manager, not the image or compose file
- [ ] Container: non-root, read-only FS, `cap_drop: ALL`, `no-new-privileges` (all set in `docker-compose.yml`)
- [ ] TLS + HSTS terminated at the load balancer
- [ ] `pip-audit` / Dependabot wired into CI (pip-audit is in `.github/workflows/ci.yml`)

## Reporting a vulnerability

Open a private security advisory on the GitHub repository, or email the address
in the repository profile. Please do not open a public issue for an undisclosed
vulnerability.
