"""Deterministic security scanner: secrets, SQLi, and every pattern rule.

Each rule has at least one positive case and one negative / false-positive case.
"""

from __future__ import annotations

import pytest

from models import FindingCategory, Severity
from scanner import PATTERN_RULES, scan_source


def _scan(src: str, threshold: float = 4.0):
    return scan_source(src, "security_pattern_scanner", threshold, lambda *p: "id:" + "|".join(map(str, p)))


def _cats(src: str) -> set[FindingCategory]:
    return {f.category for f in _scan(src)}


# --------------------------------------------------------------------------- #
# Secret signatures
# --------------------------------------------------------------------------- #


def test_aws_access_key_detected() -> None:
    findings = _scan('KEY = "AKIAIOSFODNN7EXAMPLE"\n')
    assert findings and findings[0].category is FindingCategory.HARDCODED_SECRET
    assert findings[0].severity is Severity.CRITICAL
    # evidence is redacted: the full key must not appear verbatim
    assert "AKIAIOSFODNN7EXAMPLE" not in (findings[0].evidence or "")
    assert "*" in (findings[0].evidence or "")


def test_aws_secret_access_key_detected() -> None:
    src = 'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n'
    assert FindingCategory.HARDCODED_SECRET in _cats(src)


def test_github_pat_detected() -> None:
    src = 'token = "ghp_' + "a" * 36 + '"\n'
    assert FindingCategory.HARDCODED_SECRET in _cats(src)


def test_slack_token_detected() -> None:
    assert FindingCategory.HARDCODED_SECRET in _cats('t = "xoxb-123456789012-abcdefghijkl"\n')


def test_private_key_block_detected() -> None:
    assert FindingCategory.HARDCODED_SECRET in _cats("k = '''-----BEGIN RSA PRIVATE KEY-----'''\n")


def test_database_url_with_credentials_detected() -> None:
    assert FindingCategory.HARDCODED_SECRET in _cats('DB = "postgres://u:p4ssword@db.internal:5432/app"\n')


def test_credential_assignment_detected() -> None:
    assert FindingCategory.HARDCODED_SECRET in _cats('password = "s3cr3t-value-here"\n')


def test_high_entropy_literal_detected() -> None:
    src = 'blob = "aGVsbG9Xb3JsZDEyMzQ1Njc4OTBhYmNkZWY="\n'
    assert FindingCategory.HARDCODED_SECRET in _cats(src)


@pytest.mark.parametrize(
    "line",
    [
        'API_KEY = os.environ["API_KEY"]',
        'password = getenv("PASSWORD")',
        'token = ""',
        'secret = "changeme"',
        'api_key = "<your-key-here>"',
        "PASSWORD = settings.password",
    ],
)
def test_secret_false_positives_suppressed(line: str) -> None:
    assert FindingCategory.HARDCODED_SECRET not in _cats(line + "\n")


def test_plain_english_string_not_high_entropy() -> None:
    assert _scan('msg = "the quick brown fox jumped over"\n') == []


# --------------------------------------------------------------------------- #
# SQL injection
# --------------------------------------------------------------------------- #


def test_sql_string_concat_detected() -> None:
    src = 'cur.execute("SELECT * FROM users WHERE id = " + user_id)\n'
    findings = _scan(src)
    assert any(f.category is FindingCategory.SQL_INJECTION for f in findings)
    assert findings[0].severity is Severity.CRITICAL


def test_sql_fstring_detected() -> None:
    src = 'cur.execute(f"SELECT * FROM t WHERE x = {value}")\n'
    assert FindingCategory.SQL_INJECTION in _cats(src)


def test_parameterised_query_not_flagged() -> None:
    src = 'cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))\n'
    assert FindingCategory.SQL_INJECTION not in _cats(src)


def test_plain_string_with_select_not_flagged() -> None:
    assert FindingCategory.SQL_INJECTION not in _cats('doc = "select the file from the menu"\n')


# --------------------------------------------------------------------------- #
# Pattern rules — positive + negative for each
# --------------------------------------------------------------------------- #

RULE_CASES: list[tuple[str, FindingCategory, str, str]] = [
    (
        "subprocess_shell_true",
        FindingCategory.COMMAND_INJECTION,
        'subprocess.run("ls " + d, shell=True)\n',
        'subprocess.run(["ls", d])\n',
    ),
    (
        "os_system_popen",
        FindingCategory.COMMAND_INJECTION,
        'os.system("rm -rf " + path)\n',
        "os.path.exists(path)\n",
    ),
    (
        "pickle_load",
        FindingCategory.INSECURE_DESERIALIZATION,
        "obj = pickle.loads(data)\n",
        "obj = json.loads(data)\n",
    ),
    (
        "yaml_unsafe_load",
        FindingCategory.INSECURE_DESERIALIZATION,
        "cfg = yaml.load(text)\n",
        "cfg = yaml.safe_load(text)\n",
    ),
    (
        "weak_hash",
        FindingCategory.WEAK_CRYPTO,
        "h = hashlib.md5(payload).hexdigest()\n",
        "h = hashlib.sha256(payload).hexdigest()\n",
    ),
    (
        "password_fast_hash",
        FindingCategory.WEAK_PASSWORD_HASH,
        "stored = hashlib.sha256(password.encode()).hexdigest()\n",
        "stored = argon2.hash(password)\n",
    ),
    (
        "insecure_random_secret",
        FindingCategory.WEAK_CRYPTO,
        "session_id = random.randint(0, 999999)\n",
        "session_id = secrets.token_hex(16)\n",
    ),
    (
        "tls_verification_disabled",
        FindingCategory.INSECURE_TRANSPORT,
        "requests.get(url, verify=False)\n",
        "requests.get(url, timeout=10)\n",
    ),
    (
        "insecure_http_url",
        FindingCategory.INSECURE_TRANSPORT,
        'BASE = "http://api.production.internal/v1"\n',
        'BASE = "https://api.production.internal/v1"\n',
    ),
    (
        "user_input_file_path",
        FindingCategory.PATH_TRAVERSAL,
        "return open(request.args['file']).read()\n",
        "return open(BASE / safe_name).read()\n",
    ),
    (
        "ssrf_dynamic_request",
        FindingCategory.SSRF,
        "requests.get(request.args['url'])\n",
        "requests.get('https://api.example.com/health')\n",
    ),
    (
        "jwt_alg_none",
        FindingCategory.SECURITY_MISCONFIG,
        'jwt.decode(tok, key, algorithms=["none"])\n',
        'jwt.decode(tok, key, algorithms=["RS256"])\n',
    ),
    (
        "jwt_verify_disabled",
        FindingCategory.SECURITY_MISCONFIG,
        "jwt.decode(tok, key, verify=False)\n",
        "jwt.decode(tok, key, algorithms=['HS256'])\n",
    ),
    (
        "debug_server_enabled",
        FindingCategory.SECURITY_MISCONFIG,
        "app.run(host='0.0.0.0', debug=True)\n",
        "app.run(host='0.0.0.0')\n",
    ),
]


@pytest.mark.parametrize(
    ("rule_id", "category", "positive", "negative"), RULE_CASES, ids=[c[0] for c in RULE_CASES]
)
def test_pattern_rule_positive(rule_id: str, category: FindingCategory, positive: str, negative: str) -> None:
    assert category in _cats(positive), f"{rule_id} should fire on: {positive!r}"


@pytest.mark.parametrize(
    ("rule_id", "category", "positive", "negative"), RULE_CASES, ids=[c[0] for c in RULE_CASES]
)
def test_pattern_rule_negative(rule_id: str, category: FindingCategory, positive: str, negative: str) -> None:
    assert category not in _cats(negative), f"{rule_id} should NOT fire on: {negative!r}"


def test_nosec_comment_suppresses_rule() -> None:
    assert FindingCategory.COMMAND_INJECTION not in _cats("os.system(cmd)  # nosec: reviewed\n")


def test_usedforsecurity_false_suppresses_weak_hash() -> None:
    assert FindingCategory.WEAK_CRYPTO not in _cats("h = hashlib.md5(b, usedforsecurity=False)\n")


def test_every_rule_has_required_metadata() -> None:
    for rule in PATTERN_RULES:
        assert rule.rule_id and rule.title and rule.detail and rule.remediation_hint
        assert isinstance(rule.category, FindingCategory)
        assert isinstance(rule.severity, Severity)


def test_localhost_http_url_not_flagged() -> None:
    assert FindingCategory.INSECURE_TRANSPORT not in _cats('DEV = "http://localhost:8000"\n')


def test_long_line_is_skipped_redos_guard() -> None:
    # A pathological line longer than the regex cap must be skipped, not scanned.
    line = "x = '" + "A" * 5000 + "'\n"
    assert _scan(line) == []
