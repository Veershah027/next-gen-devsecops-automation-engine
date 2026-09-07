"""Configuration validation (Settings)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from main import Settings


def test_defaults_are_valid() -> None:
    s = Settings()
    assert s.environment == "development"
    assert s.is_production is False
    assert s.webhook_enabled is False
    assert s.persistence_enabled is False


def test_production_flag() -> None:
    assert Settings(environment="production").is_production is True


@pytest.mark.parametrize("value", ["prod", "dev", "PRODUCTION ", "", "staging-eu"])
def test_invalid_environment_rejected(value: str) -> None:
    with pytest.raises(ValidationError):
        Settings(environment=value)


@pytest.mark.parametrize("value", ["INFO", "debug", "Warning", "ERROR"])
def test_log_level_accepts_known_levels(value: str) -> None:
    assert Settings(log_level=value).log_level == value.upper()


def test_log_level_rejects_unknown() -> None:
    with pytest.raises(ValidationError):
        Settings(log_level="LOUD")


@pytest.mark.parametrize(
    "url",
    [
        "http://api.github.com",  # not https
        "https://evil.example.com",  # not an allowed host
        "https://api.github.com.evil.co",  # look-alike host
        "ftp://api.github.com",
        "not-a-url",
    ],
)
def test_invalid_github_base_rejected(url: str) -> None:
    with pytest.raises(ValidationError):
        Settings(github_api_base=url)


def test_valid_github_bases_accepted() -> None:
    s = Settings(
        github_api_base="https://api.github.com/",
        github_raw_base="https://raw.githubusercontent.com",
    )
    assert s.github_api_base == "https://api.github.com"  # trailing slash trimmed


@pytest.mark.parametrize(
    "repo",
    ["octocat", "/hello", "octocat/", "octo cat/repo", "OCTOCAT/REPO/extra", "../repo"],
)
def test_invalid_repo_spec_rejected(repo: str) -> None:
    with pytest.raises(ValidationError):
        Settings(webhook_allowed_repos=[repo])


def test_repo_spec_normalised_to_lowercase() -> None:
    s = Settings(webhook_allowed_repos=["OctoCat/Hello-World"])
    assert s.webhook_allowed_repos == ["octocat/hello-world"]


def test_body_size_bounds_enforced() -> None:
    with pytest.raises(ValidationError):
        Settings(max_request_body_bytes=10)  # below the 1 KiB floor
    with pytest.raises(ValidationError):
        Settings(max_concurrent_pipelines=0)


def test_cors_origins_is_a_list() -> None:
    s = Settings(cors_allow_origins=["https://dash.example.com"])
    assert s.cors_allow_origins == ["https://dash.example.com"]
