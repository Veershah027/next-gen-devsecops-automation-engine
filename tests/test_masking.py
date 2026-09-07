"""Secret masking before any LLM egress."""

from __future__ import annotations

from scanner import mask_secrets


def test_aws_key_is_masked() -> None:
    out = mask_secrets('AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"')
    assert "AKIAIOSFODNN7EXAMPLE" not in out
    assert "<redacted:" in out


def test_connection_string_is_masked() -> None:
    out = mask_secrets('DB = "postgres://admin:SuperSecret123@10.0.0.5:5432/prod"')
    assert "SuperSecret123" not in out
    assert "admin:SuperSecret123" not in out


def test_github_token_is_masked() -> None:
    out = mask_secrets("token = 'ghp_" + "b" * 36 + "'")
    assert "ghp_" + "b" * 36 not in out


def test_private_key_block_is_masked() -> None:
    block = "-----BEGIN RSA PRIVATE KEY-----\nMIIabc123\n-----END RSA PRIVATE KEY-----"
    out = mask_secrets(block)
    assert "MIIabc123" not in out


def test_high_entropy_literal_is_masked() -> None:
    out = mask_secrets("key = 'aGVsbG9Xb3JsZDEyMzQ1Njc4OTBhYg=='")
    assert "aGVsbG9Xb3JsZDEyMzQ1Njc4OTBhYg==" not in out


def test_ordinary_code_survives_masking() -> None:
    src = "def add(a, b):\n    return a + b  # simple helper\n"
    assert mask_secrets(src) == src


def test_masking_preserves_line_count_and_structure() -> None:
    src = 'x = 1\nSECRET = "AKIAIOSFODNN7EXAMPLE"\ny = x + 2\n'
    out = mask_secrets(src)
    assert out.splitlines()[0] == "x = 1"
    assert out.splitlines()[2] == "y = x + 2"
    assert out.count("\n") == src.count("\n")


def test_short_strings_are_not_masked() -> None:
    src = 'greeting = "hello"\nname = "world"\n'
    assert mask_secrets(src) == src
