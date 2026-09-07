"""Input validation for the analyze payload."""

from __future__ import annotations

import pytest

from main import validate_analyze_request
from models import MAX_SOURCE_BYTES, AnalyzeRequest


def _req(**kw: object) -> AnalyzeRequest:
    kw.setdefault("source_code", "x = 1\n")
    return AnalyzeRequest(**kw)  # type: ignore[arg-type]


def test_valid_python_passes() -> None:
    out = validate_analyze_request(_req(source_code="def f():\n    return 1\n"))
    assert out.language == "python"


def test_unsupported_language_rejected() -> None:
    with pytest.raises(ValueError, match="python"):
        validate_analyze_request(_req(language="javascript"))


def test_oversized_source_rejected() -> None:
    with pytest.raises(ValueError, match="exceeds"):
        validate_analyze_request(_req(source_code="#" + "a" * (MAX_SOURCE_BYTES + 1)))


def test_nul_byte_rejected() -> None:
    with pytest.raises(ValueError, match="NUL"):
        validate_analyze_request(_req(source_code="x = 1\x00\n"))


def test_empty_source_rejected_by_schema() -> None:
    with pytest.raises(Exception):
        AnalyzeRequest(source_code="")


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("../../etc/passwd", "passwd"),
        ("/abs/path/thing.py", "thing.py"),
        ("weird\\windows\\name.py", "name.py"),
        ("...dots.py", "dots.py"),
        ("   ", "submission.py"),
        ("nul\x00name.py", "nulname.py"),
    ],
)
def test_filename_is_sanitised(raw: str, expected: str) -> None:
    out = validate_analyze_request(_req(filename=raw))
    assert out.filename == expected
    assert "/" not in out.filename and "\\" not in out.filename


def test_unknown_field_rejected() -> None:
    with pytest.raises(Exception):
        AnalyzeRequest(source_code="x=1", surprise=True)  # type: ignore[call-arg]
