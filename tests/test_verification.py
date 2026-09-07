"""Patch verification: parse -> re-scan -> verdict."""

from __future__ import annotations

from models import FindingCategory, PatchType, ValidationStatus
from verification import verify_patch


def test_valid_secret_fix_is_validated(make_finding) -> None:
    finding = make_finding(FindingCategory.HARDCODED_SECRET)
    patch = 'import os\nAPI_KEY = os.environ["API_KEY"]\n'
    result = verify_patch(finding, patch, PatchType.SNIPPET)
    assert result.status is ValidationStatus.VALIDATED
    assert result.parsed_ok is True
    assert result.finding_resolved is True


def test_patch_that_still_contains_the_vuln_is_unresolved(make_finding) -> None:
    finding = make_finding(FindingCategory.SQL_INJECTION)
    patch = 'cur.execute("SELECT * FROM t WHERE id = " + user_id)\n'
    result = verify_patch(finding, patch, PatchType.SNIPPET)
    assert result.status is ValidationStatus.UNRESOLVED
    assert result.finding_resolved is False
    assert FindingCategory.SQL_INJECTION in result.residual_categories


def test_syntactically_invalid_patch_is_rejected(make_finding) -> None:
    finding = make_finding(FindingCategory.DANGEROUS_CALL)
    result = verify_patch(finding, "def broken(:\n    pass\n", PatchType.SNIPPET)
    assert result.status is ValidationStatus.REJECTED
    assert result.parsed_ok is False
    assert any("not valid Python" in e for e in result.errors)


def test_truncated_patch_is_rejected(make_finding) -> None:
    finding = make_finding(FindingCategory.HARDCODED_SECRET)
    result = verify_patch(finding, "API_KEY = os.environ.get(\n", PatchType.SNIPPET)
    assert result.status is ValidationStatus.REJECTED


def test_ellipsis_marker_is_rejected(make_finding) -> None:
    finding = make_finding(FindingCategory.HARDCODED_SECRET)
    patch = "import os\nAPI_KEY = os.environ['API_KEY']\n# ... rest of the code unchanged ...\n"
    result = verify_patch(finding, patch, PatchType.SNIPPET)
    assert result.status is ValidationStatus.REJECTED


def test_guidance_patch_is_not_checked(make_finding) -> None:
    finding = make_finding(FindingCategory.SYNTAX)
    result = verify_patch(finding, "# fix the syntax error\n", PatchType.GUIDANCE)
    assert result.status is ValidationStatus.NOT_CHECKED


def test_dangerous_call_fix_re_scanned_via_ast(make_finding) -> None:
    finding = make_finding(FindingCategory.DANGEROUS_CALL)
    good = "import ast\nvalue = ast.literal_eval(raw)\n"
    bad = "value = eval(raw)\n"
    assert verify_patch(finding, good, PatchType.SNIPPET).status is ValidationStatus.VALIDATED
    assert verify_patch(finding, bad, PatchType.SNIPPET).status is ValidationStatus.UNRESOLVED


def test_command_injection_fix_validated(make_finding) -> None:
    finding = make_finding(FindingCategory.COMMAND_INJECTION)
    patch = 'import subprocess\nsubprocess.run(["git", "clone", "--", url], check=True)\n'
    assert verify_patch(finding, patch, PatchType.SNIPPET).status is ValidationStatus.VALIDATED


def test_weak_crypto_fix_validated(make_finding) -> None:
    finding = make_finding(FindingCategory.WEAK_CRYPTO)
    patch = "import hashlib\ndigest = hashlib.sha256(data).hexdigest()\n"
    assert verify_patch(finding, patch, PatchType.SNIPPET).status is ValidationStatus.VALIDATED


def test_empty_patch_rejected(make_finding) -> None:
    finding = make_finding(FindingCategory.HARDCODED_SECRET)
    assert verify_patch(finding, "   \n", PatchType.SNIPPET).status is ValidationStatus.REJECTED
