"""Webhook HMAC, payload parsing, path safety and SSRF guards."""

from __future__ import annotations

import hashlib
import hmac
import json

import pytest

from main import Settings, build_webhook_plan
from models import UpstreamFetchError, WebhookError
from scanner import assert_allowed_github_url, normalize_repo_path, verify_github_signature

SECRET = "s3cr3t-webhook-key"


def _sig(body: bytes, secret: str = SECRET) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


# --------------------------------------------------------------------------- #
# HMAC
# --------------------------------------------------------------------------- #


def test_valid_signature_accepted() -> None:
    body = b'{"hello":"world"}'
    assert verify_github_signature(SECRET, body, _sig(body)) is True


def test_invalid_signature_rejected() -> None:
    assert verify_github_signature(SECRET, b"body", "sha256=deadbeef") is False


def test_missing_signature_rejected() -> None:
    assert verify_github_signature(SECRET, b"body", None) is False
    assert verify_github_signature(SECRET, b"body", "") is False


def test_wrong_secret_rejected() -> None:
    body = b'{"a":1}'
    assert verify_github_signature("other-secret", body, _sig(body)) is False


def test_signature_without_prefix_rejected() -> None:
    body = b"x"
    raw = hmac.new(SECRET.encode(), body, hashlib.sha256).hexdigest()
    assert verify_github_signature(SECRET, body, raw) is False


# --------------------------------------------------------------------------- #
# Path safety
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "path",
    ["../secrets.py", "a/../../b.py", "/etc/passwd", "back\\slash.py", "with\x00nul.py", ".."],
)
def test_normalize_repo_path_rejects_unsafe(path: str) -> None:
    assert normalize_repo_path(path) is None


@pytest.mark.parametrize("path", ["src/app.py", "a/b/c/mod.py", "single.py"])
def test_normalize_repo_path_accepts_clean(path: str) -> None:
    assert normalize_repo_path(path) == path


# --------------------------------------------------------------------------- #
# SSRF host allow-list
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "url",
    [
        "http://raw.githubusercontent.com/o/r/sha/f.py",  # not https
        "https://raw.githubusercontent.com.evil.net/x",  # look-alike
        "https://169.254.169.254/latest/meta-data/",  # cloud metadata
        "https://localhost:8000/x",
        "https://gitlab.com/o/r/raw/f.py",
        "file:///etc/passwd",
    ],
)
def test_disallowed_fetch_urls_rejected(url: str) -> None:
    with pytest.raises(UpstreamFetchError):
        assert_allowed_github_url(url)


@pytest.mark.parametrize(
    "url",
    [
        "https://raw.githubusercontent.com/octo/repo/abc123/src/app.py",
        "https://api.github.com/repos/octo/repo/pulls/1/files",
    ],
)
def test_allowed_github_urls_pass(url: str) -> None:
    assert assert_allowed_github_url(url) == url


# --------------------------------------------------------------------------- #
# Payload → plan parsing
# --------------------------------------------------------------------------- #


def _settings() -> Settings:
    return Settings(github_webhook_secret=SECRET)


def test_push_plan_keeps_python_files_only() -> None:
    payload = {
        "ref": "refs/heads/main",
        "after": "a" * 40,
        "repository": {"full_name": "octo/demo"},
        "commits": [
            {"added": ["src/new.py", "README.md"], "modified": ["app/svc.py", "../evil.py"]},
        ],
    }
    plan = build_webhook_plan("push", payload, _settings())
    assert plan.repository == "octo/demo"
    assert set(plan.explicit_files) == {"src/new.py", "app/svc.py"}
    assert "README.md" in plan.skipped
    assert "../evil.py" in plan.skipped


def test_push_without_sha_rejected() -> None:
    with pytest.raises(WebhookError):
        build_webhook_plan("push", {"repository": {"full_name": "o/r"}, "commits": []}, _settings())


def test_zero_sha_push_rejected() -> None:
    payload = {"after": "0" * 40, "repository": {"full_name": "o/r"}, "commits": []}
    with pytest.raises(WebhookError):
        build_webhook_plan("push", payload, _settings())


def test_pull_request_plan_carries_number() -> None:
    payload = {
        "action": "opened",
        "pull_request": {
            "number": 7,
            "head": {"sha": "b" * 40, "ref": "feature", "repo": {"full_name": "o/r"}},
        },
    }
    plan = build_webhook_plan("pull_request", payload, _settings())
    assert plan.pr_number == 7
    assert plan.repository == "o/r"


def test_pull_request_ignored_action_is_noop_plan() -> None:
    payload = {
        "action": "labeled",
        "pull_request": {"number": 7, "head": {"sha": "b" * 40, "ref": "f", "repo": {"full_name": "o/r"}}},
    }
    plan = build_webhook_plan("pull_request", payload, _settings())
    assert plan.pr_number is None and plan.explicit_files == ()


def test_unhandled_event_rejected() -> None:
    with pytest.raises(WebhookError):
        build_webhook_plan("issues", {}, _settings())


# --------------------------------------------------------------------------- #
# Endpoint behaviour
# --------------------------------------------------------------------------- #


def test_webhook_disabled_returns_503(app_factory) -> None:
    from fastapi.testclient import TestClient

    with TestClient(app_factory(github_webhook_secret=None)) as c:
        assert c.post("/api/v1/webhook", json={}).status_code == 503


def test_webhook_ping_pong(client) -> None:
    body = b'{"zen":"hello"}'
    r = client.post(
        "/api/v1/webhook",
        content=body,
        headers={"x-github-event": "ping", "x-hub-signature-256": _sig(body, "unit-test-webhook-secret")},
    )
    assert r.status_code == 202 and r.json()["note"] == "pong"


def test_webhook_bad_signature_401(client) -> None:
    r = client.post(
        "/api/v1/webhook",
        content=b"{}",
        headers={"x-github-event": "ping", "x-hub-signature-256": "sha256=nope"},
    )
    assert r.status_code == 401


def test_webhook_malformed_json_400(client) -> None:
    body = b"not json{"
    r = client.post(
        "/api/v1/webhook",
        content=body,
        headers={"x-github-event": "push", "x-hub-signature-256": _sig(body, "unit-test-webhook-secret")},
    )
    assert r.status_code == 400


def test_webhook_unsupported_event_not_accepted(client) -> None:
    body = json.dumps({"a": 1}).encode()
    r = client.post(
        "/api/v1/webhook",
        content=body,
        headers={"x-github-event": "star", "x-hub-signature-256": _sig(body, "unit-test-webhook-secret")},
    )
    assert r.status_code == 202 and r.json()["accepted"] is False


def test_webhook_repo_not_in_allowlist_401(app_factory) -> None:
    from fastapi.testclient import TestClient

    payload = json.dumps(
        {
            "after": "c" * 40,
            "ref": "refs/heads/main",
            "repository": {"full_name": "octo/demo"},
            "commits": [{"added": ["a.py"], "modified": []}],
        }
    ).encode()
    app = app_factory(github_webhook_secret=SECRET, webhook_allowed_repos=["someone/else"])
    with TestClient(app) as c:
        r = c.post(
            "/api/v1/webhook",
            content=payload,
            headers={"x-github-event": "push", "x-hub-signature-256": _sig(payload)},
        )
    assert r.status_code == 401
