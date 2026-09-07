"""Deterministic security primitives: entropy, redaction, masking, HMAC, SSRF
guards, and the regex signature / pattern-rule tables used by the scanner agent.

Everything here is pure and synchronous so it can be unit-tested directly.
Nothing in this module executes analysed code.
"""

from __future__ import annotations

import ast
import hashlib
import hmac
import math
import re
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Final
from urllib.parse import urlsplit

from models import (
    ALLOWED_GITHUB_HOSTS,
    MAX_REGEX_LINE,
    CodePosition,
    Finding,
    FindingCategory,
    Severity,
    UpstreamFetchError,
)

# ===========================================================================
# Entropy + redaction
# ===========================================================================


FindingIdFn = Callable[..., str]


def shannon_entropy(token: str) -> float:
    """Shannon entropy of ``token`` in bits per character."""

    if not token:
        return 0.0
    counts = Counter(token)
    length = len(token)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def redact(text: str, *, keep: int = 4) -> str:
    """Redact the middle of a sensitive token for safe logging / evidence."""

    text = text.strip()
    if len(text) <= keep * 2:
        return "*" * len(text)
    return f"{text[:keep]}{'*' * (len(text) - keep * 2)}{text[-keep:]}"


# ===========================================================================
# Secret masking (egress) — over-masks by design
# ===========================================================================

# Multi-line secret: a whole PEM private-key block.
_PEM_BLOCK = re.compile(r"-----BEGIN[^-]*PRIVATE KEY-----.*?-----END[^-]*PRIVATE KEY-----", re.DOTALL)
# Single-line credential shapes.
_MASK_LINE_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    re.compile(r"(?<![A-Z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Z0-9])"),
    re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}"),
    re.compile(r"gh[pousr]_[0-9A-Za-z]{20,}"),
    re.compile(r"AIza[0-9A-Za-z_\-]{35}"),
    re.compile(r"[a-z][a-z0-9+.\-]*://[^\s:@/]+:[^\s:@/]+@[^\s/]+"),
    re.compile(r"(['\"])([A-Za-z0-9+/=_\-]{20,})\1"),
)


def _mask_span(value: str) -> str:
    return f"<redacted:{len(value)}>"


def mask_secrets(text: str) -> str:
    """Blank anything that looks like a credential before it can leave the process.

    Deliberately over-masks. Line structure and the trailing newline are
    preserved so a code window stays readable to the model.
    """

    text = _PEM_BLOCK.sub(lambda m: _mask_span(m.group(0)), text)
    out: list[str] = []
    for line in text.split("\n"):
        masked = line
        if 0 < len(masked) <= MAX_REGEX_LINE:
            for pattern in _MASK_LINE_PATTERNS:
                masked = pattern.sub(lambda m: _mask_span(m.group(0)), masked)
        out.append(masked)
    return "\n".join(out)


# ===========================================================================
# Filename / path safety
# ===========================================================================

_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


def sanitize_filename(name: str) -> str:
    """Reduce an arbitrary path to a safe, log-injection-free basename."""

    candidate = _CONTROL_CHARS.sub("", (name or "").strip().replace("\\", "/"))
    candidate = PurePosixPath(candidate).name
    candidate = candidate.lstrip(". ") or "submission.py"
    return candidate[:255]


def normalize_repo_path(path: str) -> str | None:
    """Return a safe repo-relative POSIX path, or ``None`` if it is suspicious."""

    if not path or "\x00" in path or "\\" in path:
        return None
    posix = PurePosixPath(path.strip())
    if posix.is_absolute() or any(part in ("..", "") for part in posix.parts):
        return None
    return str(posix)


# ===========================================================================
# Webhook / SSRF guards
# ===========================================================================


def verify_github_signature(secret: str, body: bytes, signature_header: str | None) -> bool:
    """Constant-time HMAC-SHA256 verification of ``X-Hub-Signature-256``."""

    if not signature_header or not signature_header.startswith("sha256="):
        return False
    expected = "sha256=" + hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature_header)


def assert_allowed_github_url(url: str) -> str:
    """Raise ``UpstreamFetchError`` unless ``url`` targets a pinned GitHub host."""

    parts = urlsplit(url)
    if parts.scheme != "https" or parts.hostname not in ALLOWED_GITHUB_HOSTS:
        raise UpstreamFetchError(f"refusing to fetch non-allowlisted URL host: {parts.hostname!r}")
    return url


# ===========================================================================
# Secret detection signatures
# ===========================================================================

SecretSignature = tuple[str, str, "re.Pattern[str]", Severity]

SECRET_SIGNATURES: Final[tuple[SecretSignature, ...]] = (
    (
        "aws_access_key_id",
        "AWS access key identifier",
        re.compile(r"(?<![A-Z0-9])(AKIA|ASIA)[0-9A-Z]{16}(?![A-Z0-9])"),
        Severity.CRITICAL,
    ),
    (
        "aws_secret_access_key",
        "AWS secret access key",
        re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*['\"][A-Za-z0-9/+=]{40}['\"]"),
        Severity.CRITICAL,
    ),
    (
        "private_key_block",
        "PEM-encoded private key",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
        Severity.CRITICAL,
    ),
    ("slack_token", "Slack API token", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}"), Severity.HIGH),
    (
        "github_pat",
        "GitHub personal access token",
        re.compile(r"gh[pousr]_[0-9A-Za-z]{36,}"),
        Severity.HIGH,
    ),
    (
        "google_api_key",
        "Google API key",
        re.compile(r"AIza[0-9A-Za-z_\-]{35}"),
        Severity.HIGH,
    ),
    (
        "generic_assignment",
        "Credential-like assignment to a literal",
        re.compile(
            r"(?i)\b(?:api[_-]?key|secret|passwd|password|token|access[_-]?key|auth)\b"
            r"\s*[:=]\s*['\"][^'\"\n]{8,}['\"]"
        ),
        Severity.HIGH,
    ),
    (
        "connection_string",
        "URL with embedded credentials",
        re.compile(r"[a-z][a-z0-9+.\-]*://[^\s:@/]+:[^\s:@/]+@[^\s/]+"),
        Severity.HIGH,
    ),
)

# Values that look like credential assignments but are placeholders, not secrets.
_SECRET_FALSE_POSITIVE = re.compile(
    r"(?i)(?:=\s*['\"](?:|x+|\.+|changeme|your[_-].*|<[^>]+>|\$\{[^}]+\}|None|null|example|"
    r"placeholder|redacted|dummy|test|fake|xxx+|\*+)['\"]|os\.(?:environ|getenv)|"
    r"getenv\(|environ\[|Field\(|settings\.|config\.|config\[)"
)

_STRING_LITERAL = re.compile(r"['\"]([A-Za-z0-9+/=_\-]{20,})['\"]")
_SQL_KEYWORDS = re.compile(r"(?i)\b(select|insert|update|delete)\b.*\bfrom\b|\binto\b")
_SQL_CONCAT = re.compile(
    r"(?i)(execute|executemany|cursor\.execute|raw)\s*\(\s*"
    r"(?:f?['\"].*?['\"]\s*(?:%|\+|\.format)|['\"].*?['\"]\s*\+)"
)
_SQL_FSTRING = re.compile(r"(?i)(execute|executemany|raw)\s*\(\s*f['\"].*?\{.*?\}.*?['\"]")


# ===========================================================================
# Pattern rules (Phase 5) — regex-detectable, reasonable confidence
# ===========================================================================


@dataclass(frozen=True, slots=True)
class PatternRule:
    rule_id: str
    category: FindingCategory
    severity: Severity
    title: str
    detail: str
    remediation_hint: str
    pattern: re.Pattern[str]
    suppress_if: re.Pattern[str] | None = None


_NOSEC = re.compile(r"#\s*(?:nosec|noqa|nofix|safe)\b")

PATTERN_RULES: Final[tuple[PatternRule, ...]] = (
    PatternRule(
        "subprocess_shell_true",
        FindingCategory.COMMAND_INJECTION,
        Severity.HIGH,
        "subprocess call with shell=True",
        "Passing shell=True runs the command through /bin/sh; any interpolated value becomes "
        "a shell-injection vector.",
        "Pass the command as an argument list and drop shell=True, e.g. "
        "subprocess.run(['git', 'clone', url], check=True).",
        re.compile(r"\bsubprocess\.(?:run|call|check_call|check_output|Popen)\s*\([^)]*shell\s*=\s*True"),
        _NOSEC,
    ),
    PatternRule(
        "os_system_popen",
        FindingCategory.COMMAND_INJECTION,
        Severity.HIGH,
        "os.system() / os.popen() invocation",
        "os.system and os.popen execute a string through the shell and are near-impossible "
        "to use safely with any dynamic input.",
        "Use subprocess.run([...]) with an argument list and check=True.",
        re.compile(r"\bos\.(?:system|popen)\s*\("),
        _NOSEC,
    ),
    PatternRule(
        "pickle_load",
        FindingCategory.INSECURE_DESERIALIZATION,
        Severity.HIGH,
        "Deserialization via pickle",
        "pickle.load / pickle.loads execute arbitrary objects during unpickling. Never "
        "unpickle data from an untrusted source.",
        "Use json for data interchange, or a schema-validated format; if pickle is "
        "unavoidable, sign the payload and verify before loading.",
        re.compile(r"\b(?:cPickle|pickle)\.loads?\s*\("),
        _NOSEC,
    ),
    PatternRule(
        "yaml_unsafe_load",
        FindingCategory.INSECURE_DESERIALIZATION,
        Severity.HIGH,
        "Unsafe YAML deserialization",
        "yaml.load without a safe loader (and yaml.unsafe_load) can construct arbitrary "
        "Python objects, enabling code execution.",
        "Use yaml.safe_load(...) or pass Loader=yaml.SafeLoader.",
        re.compile(r"\byaml\.(?:unsafe_load|load)\s*\("),
        re.compile(r"Loader\s*=\s*(?:yaml\.)?(?:C?SafeLoader)"),
    ),
    PatternRule(
        "weak_hash",
        FindingCategory.WEAK_CRYPTO,
        Severity.MEDIUM,
        "Weak hash function (MD5 / SHA-1)",
        "MD5 and SHA-1 are broken for collision resistance and unsuitable for integrity or signature use.",
        "Use SHA-256 or SHA-3; if the hash is genuinely non-security, add usedforsecurity=False.",
        re.compile(r"\bhashlib\.(?:md5|sha1)\s*\("),
        re.compile(r"usedforsecurity\s*=\s*False"),
    ),
    PatternRule(
        "password_fast_hash",
        FindingCategory.WEAK_PASSWORD_HASH,
        Severity.HIGH,
        "Password hashed with a fast digest",
        "Hashing passwords with md5/sha-1/sha-256 (even salted) is brute-forceable at "
        "billions of guesses per second on a GPU.",
        "Use a slow, salted KDF: argon2 (argon2-cffi), bcrypt, or "
        "hashlib.scrypt / pbkdf2_hmac with a high iteration count.",
        re.compile(
            r"(?i)\b(?:password|passwd|pwd)\b[^\n]*\bhashlib\.(?:md5|sha1|sha224|sha256|sha384|sha512)\s*\("
            r"|\bhashlib\.(?:md5|sha1|sha256)\s*\([^)]*\b(?:password|passwd|pwd)\b"
        ),
    ),
    PatternRule(
        "insecure_random_secret",
        FindingCategory.WEAK_CRYPTO,
        Severity.MEDIUM,
        "Security value from the 'random' module",
        "random is a Mersenne-Twister PRNG and is predictable; it must not generate "
        "tokens, salts, nonces, or passwords.",
        "Use the 'secrets' module: secrets.token_urlsafe(), secrets.token_hex(), secrets.choice().",
        re.compile(
            r"(?i)\b(?:token|secret|salt|nonce|api[_-]?key|password|session[_-]?id)\b\s*[:=]"
            r"[^\n]*\brandom\.(?:random|randint|choice|randrange|getrandbits|sample|shuffle)\s*\("
        ),
    ),
    PatternRule(
        "tls_verification_disabled",
        FindingCategory.INSECURE_TRANSPORT,
        Severity.HIGH,
        "TLS certificate verification disabled",
        "verify=False (requests / httpx) or ssl._create_unverified_context disables "
        "certificate validation, exposing traffic to interception.",
        "Remove verify=False; if a private CA is in use, pass verify='/path/to/ca.pem'.",
        re.compile(r"\bverify\s*=\s*False\b|ssl\._create_unverified_context\s*\("),
        _NOSEC,
    ),
    PatternRule(
        "insecure_http_url",
        FindingCategory.INSECURE_TRANSPORT,
        Severity.LOW,
        "Hard-coded http:// URL",
        "Plain-text HTTP for an external host allows on-path tampering and credential capture.",
        "Use https:// for any non-local endpoint.",
        re.compile(
            r"""['"]http://(?!(?:localhost|127\.0\.0\.1|0\.0\.0\.0|169\.254\.|"""
            r"""host\.docker\.internal|example\.(?:com|org|net)))[^'"\s]+['"]"""
        ),
    ),
    PatternRule(
        "user_input_file_path",
        FindingCategory.PATH_TRAVERSAL,
        Severity.HIGH,
        "Request-controlled value used as a filesystem path",
        "Passing request data straight into open()/send_file()/os.path.join() lets an "
        "attacker read or write files outside the intended directory with '../'.",
        "Resolve against a fixed base with pathlib and verify the result stays inside it: "
        "base = Path('/data').resolve(); target = (base / name).resolve(); "
        "target.relative_to(base).",
        re.compile(
            r"\b(?:open|send_file|send_from_directory|os\.path\.join|shutil\.copy\w*|Path)\s*\("
            r"[^)]*\brequest\.(?:args|form|values|json|data|GET|POST|params|query_params)\b"
        ),
    ),
    PatternRule(
        "ssrf_dynamic_request",
        FindingCategory.SSRF,
        Severity.MEDIUM,
        "Outbound request to a request-controlled URL",
        "Fetching a URL built from request data lets an attacker reach internal services "
        "and cloud metadata endpoints (SSRF).",
        "Validate the target against an allow-list of hosts/schemes before the request and "
        "disable redirects.",
        re.compile(
            r"\b(?:requests\.(?:get|post|put|patch|delete|head|request)|httpx\.(?:get|post|request)"
            r"|urlopen|urllib\.request\.urlopen)\s*\([^)]*\brequest\.(?:args|form|values|json|GET|POST|params)\b"
        ),
    ),
    PatternRule(
        "jwt_alg_none",
        FindingCategory.SECURITY_MISCONFIG,
        Severity.CRITICAL,
        "JWT 'none' algorithm accepted",
        "Allowing the 'none' algorithm means any client can forge a token with no signature.",
        "Pin a single strong algorithm, e.g. jwt.decode(token, key, algorithms=['RS256']).",
        re.compile(r"(?i)algorithms?\s*=\s*\[?\s*['\"]none['\"]"),
    ),
    PatternRule(
        "jwt_verify_disabled",
        FindingCategory.SECURITY_MISCONFIG,
        Severity.HIGH,
        "JWT signature verification disabled",
        "jwt.decode(..., verify=False) or options={'verify_signature': False} accepts "
        "unsigned / tampered tokens.",
        "Remove the flag and pass algorithms=[...] with the verification key.",
        re.compile(r"\bjwt\.decode\s*\([^)]*(?:verify\s*=\s*False|verify_signature['\"]?\s*:\s*False)"),
    ),
    PatternRule(
        "debug_server_enabled",
        FindingCategory.SECURITY_MISCONFIG,
        Severity.MEDIUM,
        "Debug mode enabled on a web server",
        "Flask/Django debug mode exposes an interactive traceback console; on Flask the "
        "Werkzeug debugger PIN can be brute-forced to RCE.",
        "Drive debug from an environment variable that is false in production.",
        re.compile(r"\.run\s*\([^)]*debug\s*=\s*True|^\s*DEBUG\s*=\s*True\b"),
    ),
)


# ===========================================================================
# The scan
# ===========================================================================


def _make_finding(
    agent_value: str,
    finding_id: str,
    category: FindingCategory,
    severity: Severity,
    title: str,
    detail: str,
    *,
    line: int,
    column: int | None = None,
    hint: str | None = None,
    evidence: str | None = None,
) -> Finding:
    from models import AgentName  # local import to avoid an import cycle at module load

    return Finding(
        id=finding_id,
        agent=AgentName(agent_value),
        category=category,
        severity=severity,
        title=title,
        detail=detail,
        position=CodePosition(line=line, column=column),
        remediation_hint=hint,
        evidence=evidence,
    )


def scan_source(
    source: str, agent_value: str, entropy_threshold: float, finding_id: FindingIdFn
) -> list[Finding]:
    """Run every regex-based rule over ``source`` and return findings.

    ``finding_id`` is a callable ``(*parts) -> str`` supplied by the agent so ids
    stay stable and namespaced.
    """

    findings: list[Finding] = []
    for lineno, line in enumerate(source.splitlines(), start=1):
        if len(line) > MAX_REGEX_LINE:
            continue  # ReDoS guard
        findings.extend(_scan_secrets(line, lineno, agent_value, entropy_threshold, finding_id))
        findings.extend(_scan_sql(line, lineno, agent_value, finding_id))
        findings.extend(_scan_pattern_rules(line, lineno, agent_value, finding_id))
    unique: dict[str, Finding] = {f.id: f for f in findings}
    return list(unique.values())


def _scan_secrets(
    line: str, lineno: int, agent_value: str, threshold: float, finding_id: FindingIdFn
) -> list[Finding]:
    out: list[Finding] = []
    for key, label, pattern, severity in SECRET_SIGNATURES:
        match = pattern.search(line)
        if not match:
            continue
        if key in ("generic_assignment",) and _SECRET_FALSE_POSITIVE.search(line):
            continue
        out.append(
            _make_finding(
                agent_value,
                finding_id("sig", key, lineno),
                FindingCategory.HARDCODED_SECRET,
                severity,
                f"Hard-coded secret: {label}",
                f"A value matching the {label} signature is committed in source. Secrets in "
                "VCS history must be treated as compromised and rotated.",
                line=lineno,
                column=match.start(),
                hint="Load from the environment / a secrets manager and rotate the exposed value.",
                evidence=redact(match.group(0)),
            )
        )
    for match in _STRING_LITERAL.finditer(line):
        token = match.group(1)
        entropy = shannon_entropy(token)
        if entropy < threshold or token.isalpha() or token.isdigit():
            continue
        out.append(
            _make_finding(
                agent_value,
                finding_id("entropy", lineno, match.start()),
                FindingCategory.HARDCODED_SECRET,
                Severity.MEDIUM,
                "High-entropy string literal",
                f"String literal has Shannon entropy {entropy:.2f} bits/char (>= {threshold}); "
                "it may be an API key, token, or password.",
                line=lineno,
                column=match.start(),
                hint="If this is a credential, externalize it; otherwise justify it with a note.",
                evidence=redact(token),
            )
        )
    return out


def _scan_sql(line: str, lineno: int, agent_value: str, finding_id: FindingIdFn) -> list[Finding]:
    dynamic = _SQL_CONCAT.search(line) or _SQL_FSTRING.search(line)
    if not (_SQL_KEYWORDS.search(line) and dynamic):
        return []
    return [
        _make_finding(
            agent_value,
            finding_id("sqli", lineno),
            FindingCategory.SQL_INJECTION,
            Severity.CRITICAL,
            "Possible SQL injection sink",
            "A SQL statement is assembled with string concatenation / f-strings / % formatting "
            "and handed to a DB cursor. Untrusted input there is injectable.",
            line=lineno,
            column=dynamic.start(),
            hint="Use parameterized queries: cursor.execute(sql, params) with placeholders.",
            evidence=redact(line.strip(), keep=8),
        )
    ]


def _scan_pattern_rules(line: str, lineno: int, agent_value: str, finding_id: FindingIdFn) -> list[Finding]:
    out: list[Finding] = []
    for rule in PATTERN_RULES:
        match = rule.pattern.search(line)
        if not match:
            continue
        if rule.suppress_if is not None and rule.suppress_if.search(line):
            continue
        out.append(
            _make_finding(
                agent_value,
                finding_id("rule", rule.rule_id, lineno),
                rule.category,
                rule.severity,
                rule.title,
                rule.detail,
                line=lineno,
                column=match.start(),
                hint=rule.remediation_hint,
                evidence=redact(line.strip(), keep=8),
            )
        )
    return out


# ===========================================================================
# AST structural analysis (parsed, never executed)
# ===========================================================================

_DANGEROUS_CALLS: Final[frozenset[str]] = frozenset({"eval", "exec", "compile", "__import__"})


def ast_scan(
    source: str, agent_value: str, finding_id: FindingIdFn, filename: str = "submission.py"
) -> list[Finding]:
    """Parse ``source`` and report structural defects. Never compiles or runs it."""

    try:
        tree = ast.parse(source, filename=filename)
    except SyntaxError as exc:
        return [
            _make_finding(
                agent_value,
                finding_id("syntax", exc.lineno, exc.offset, exc.msg),
                FindingCategory.SYNTAX,
                Severity.CRITICAL,
                "Source does not parse",
                f"SyntaxError: {exc.msg}",
                line=exc.lineno or 1,
                column=(exc.offset - 1) if exc.offset else None,
                hint="Fix the syntax error before further analysis.",
                evidence=(exc.text or "").strip()[:400] or None,
            )
        ]
    except (ValueError, RecursionError, MemoryError) as exc:
        return [
            _make_finding(
                agent_value,
                finding_id("unparseable", type(exc).__name__),
                FindingCategory.SYNTAX,
                Severity.HIGH,
                "Source could not be parsed",
                f"{type(exc).__name__} while building the AST: {exc}",
                line=1,
                hint="Reduce nesting / size or fix encoding issues.",
            )
        ]

    findings: list[Finding] = []
    for node in ast.walk(tree):
        findings.extend(_ast_nested_loops(node, agent_value, finding_id))
        findings.extend(_ast_bare_except(node, agent_value, finding_id))
        findings.extend(_ast_dangerous_calls(node, agent_value, finding_id))
        findings.extend(_ast_mutable_defaults(node, agent_value, finding_id))
    return findings


def _loop_depth(node: ast.AST, current: int = 1) -> int:
    best = current
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.For, ast.While, ast.AsyncFor)):
            best = max(best, _loop_depth(child, current + 1))
        elif isinstance(child, (ast.If, ast.With, ast.Try)):
            best = max(best, _loop_depth(child, current))
    return best


def _ast_nested_loops(node: ast.AST, agent_value: str, finding_id: FindingIdFn) -> list[Finding]:
    if not isinstance(node, (ast.For, ast.While, ast.AsyncFor)):
        return []
    depth = _loop_depth(node)
    if depth < 3:
        return []
    return [
        _make_finding(
            agent_value,
            finding_id("nested_loop", getattr(node, "lineno", 0), depth),
            FindingCategory.PERFORMANCE,
            Severity.MEDIUM if depth == 3 else Severity.HIGH,
            f"{depth}-level nested loop",
            f"A loop nest {depth} levels deep starts here; worst-case complexity is ~O(n^{depth}). "
            "Consider hoisting invariants, vectorizing, or a set/dict membership test.",
            line=getattr(node, "lineno", 1),
            hint="Flatten the nest, precompute lookups, or lower the asymptotic cost.",
        )
    ]


def _ast_bare_except(node: ast.AST, agent_value: str, finding_id: FindingIdFn) -> list[Finding]:
    if not isinstance(node, ast.ExceptHandler) or node.type is not None:
        return []
    return [
        _make_finding(
            agent_value,
            finding_id("bare_except", node.lineno),
            FindingCategory.STYLE,
            Severity.LOW,
            "Bare 'except:' clause",
            "A bare except swallows KeyboardInterrupt / SystemExit and hides real defects.",
            line=node.lineno,
            hint="Replace with 'except SpecificError as exc:'.",
        )
    ]


def _ast_dangerous_calls(node: ast.AST, agent_value: str, finding_id: FindingIdFn) -> list[Finding]:
    if not isinstance(node, ast.Call):
        return []
    func = node.func
    target = func.id if isinstance(func, ast.Name) else func.attr if isinstance(func, ast.Attribute) else None
    if target not in _DANGEROUS_CALLS:
        return []
    return [
        _make_finding(
            agent_value,
            finding_id("dangerous_call", target, node.lineno),
            FindingCategory.DANGEROUS_CALL,
            Severity.HIGH,
            f"Use of '{target}()'",
            f"'{target}()' executes arbitrary code and is a classic RCE vector when any part of "
            "its argument is attacker-influenced.",
            line=node.lineno,
            column=node.col_offset,
            hint="Use ast.literal_eval for data, importlib for imports, or a dispatch table.",
        )
    ]


def _ast_mutable_defaults(node: ast.AST, agent_value: str, finding_id: FindingIdFn) -> list[Finding]:
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return []
    out: list[Finding] = []
    for default in (*node.args.defaults, *node.args.kw_defaults):
        if isinstance(default, (ast.List, ast.Dict, ast.Set)):
            out.append(
                _make_finding(
                    agent_value,
                    finding_id("mutable_default", node.name, node.lineno),
                    FindingCategory.STYLE,
                    Severity.LOW,
                    f"Mutable default argument in '{node.name}'",
                    "Mutable default arguments are shared across calls and leak state between invocations.",
                    line=node.lineno,
                    hint="Default to None and create the container inside the body.",
                )
            )
    return out
