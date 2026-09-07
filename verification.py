"""Patch verification: FINDING -> PATCH -> VALIDATE -> RE-SCAN -> VERDICT.

A generated patch is only worth trusting if the engine can show its work. This
module parses the patch (never executes it), rejects obviously malformed or
truncated output, then re-runs the deterministic scanner against the patched
snippet and reports whether the original finding's category still fires.
"""

from __future__ import annotations

import ast

from models import (
    MAX_PATCH_CHARS,
    Finding,
    FindingCategory,
    PatchType,
    PatchValidation,
    ValidationStatus,
)
from scanner import ast_scan, scan_source

_RESCANNABLE_BY_PATTERN: frozenset[FindingCategory] = frozenset(
    {
        FindingCategory.HARDCODED_SECRET,
        FindingCategory.SQL_INJECTION,
        FindingCategory.COMMAND_INJECTION,
        FindingCategory.PATH_TRAVERSAL,
        FindingCategory.INSECURE_DESERIALIZATION,
        FindingCategory.WEAK_CRYPTO,
        FindingCategory.WEAK_PASSWORD_HASH,
        FindingCategory.INSECURE_TRANSPORT,
        FindingCategory.SSRF,
        FindingCategory.SECURITY_MISCONFIG,
    }
)
_RESCANNABLE_BY_AST: frozenset[FindingCategory] = frozenset(
    {
        FindingCategory.SYNTAX,
        FindingCategory.PERFORMANCE,
        FindingCategory.DANGEROUS_CALL,
        FindingCategory.STYLE,
    }
)

_TRUNCATION_MARKERS = ("truncated", "rest of the code", "unchanged", "# ...", "# …", "<snip>")
_DANGLING_SUFFIXES = (",", "(", "[", "{", "\\", "+", "-", "=", ":", "&", "|", "and", "or")


def _structural_problems(code: str) -> list[str]:
    problems: list[str] = []
    stripped = code.rstrip()
    if not stripped:
        problems.append("patch is empty")
        return problems
    last = stripped.splitlines()[-1].strip()
    if last.endswith(_DANGLING_SUFFIXES):
        problems.append("patch appears to end mid-statement")
    for pair in ("()", "[]", "{}"):
        if code.count(pair[0]) != code.count(pair[1]):
            problems.append(f"unbalanced '{pair[0]}{pair[1]}'")
    lowered = code.lower()
    if any(marker in lowered for marker in _TRUNCATION_MARKERS):
        problems.append("patch contains an ellipsis / 'unchanged' marker instead of full code")
    if len(code) >= MAX_PATCH_CHARS:
        problems.append("patch reached the maximum allowed length (likely truncated)")
    return problems


def _parses(code: str) -> tuple[bool, str | None]:
    try:
        ast.parse(code)
        return True, None
    except SyntaxError as exc:
        # A bare expression fragment can still be a legitimate snippet.
        try:
            ast.parse(code, mode="eval")
            return True, None
        except SyntaxError:
            return False, f"{exc.msg} (line {exc.lineno})"


def _residual_categories(
    code: str, category: FindingCategory, entropy_threshold: float
) -> set[FindingCategory]:
    def _id(*parts: object) -> str:
        return "verify:" + "|".join(str(p) for p in parts)

    cats: set[FindingCategory] = set()
    if category in _RESCANNABLE_BY_PATTERN:
        cats |= {f.category for f in scan_source(code, "security_pattern_scanner", entropy_threshold, _id)}
    if category in _RESCANNABLE_BY_AST:
        cats |= {f.category for f in ast_scan(code, "ast_structural_parser", _id)}
    return cats


def verify_patch(
    finding: Finding,
    patch_code: str,
    patch_type: PatchType,
    *,
    entropy_threshold: float = 4.0,
) -> PatchValidation:
    """Validate a generated patch and decide whether the finding is resolved."""

    if patch_type is PatchType.GUIDANCE:
        return PatchValidation(
            status=ValidationStatus.NOT_CHECKED,
            parsed_ok=False,
            finding_resolved=None,
            errors=("advisory guidance, not a re-scannable code patch",),
        )

    problems = _structural_problems(patch_code)
    parsed_ok, parse_error = _parses(patch_code)
    if parse_error:
        problems.append(f"not valid Python: {parse_error}")

    if problems:
        return PatchValidation(
            status=ValidationStatus.REJECTED,
            parsed_ok=parsed_ok,
            finding_resolved=False,
            errors=tuple(problems),
        )

    if finding.category not in (_RESCANNABLE_BY_PATTERN | _RESCANNABLE_BY_AST):
        return PatchValidation(
            status=ValidationStatus.NOT_CHECKED,
            parsed_ok=True,
            finding_resolved=None,
            errors=(f"category '{finding.category.value}' cannot be re-scanned on a snippet",),
        )

    residual = _residual_categories(patch_code, finding.category, entropy_threshold)
    resolved = finding.category not in residual
    return PatchValidation(
        status=ValidationStatus.VALIDATED if resolved else ValidationStatus.UNRESOLVED,
        parsed_ok=True,
        finding_resolved=resolved,
        residual_categories=tuple(sorted(residual, key=lambda c: c.value)),
    )
