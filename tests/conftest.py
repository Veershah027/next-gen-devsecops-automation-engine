"""Shared fixtures. Tests never make real network calls."""

from __future__ import annotations

import sys
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import main  # noqa: E402
from models import Finding, FindingCategory, Severity  # noqa: E402

WEBHOOK_SECRET = "unit-test-webhook-secret"

VULNERABLE_SOURCE = """\
import os
import subprocess
import pickle
import hashlib
import yaml

AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
DATABASE_URL = "postgres://admin:hunter2primary@10.0.0.5:5432/prod"


def run_job(name):
    subprocess.run("process " + name, shell=True)


def load_state(blob):
    return pickle.loads(blob)


def config(text):
    return yaml.load(text)


def digest(password):
    return hashlib.md5(password.encode()).hexdigest()


def find_user(conn, username):
    conn.cursor().execute("SELECT * FROM users WHERE name = '" + username + "'")


def compute(rows, cols, cells):
    for r in rows:
        for c in cols:
            for x in cells:
                if r == x:
                    total = eval("r * c")
    return total


def read_file(path, cache={}):
    try:
        return cache[path]
    except:
        cache[path] = open(path).read()
        return cache[path]
"""

CLEAN_SOURCE = """\
import os


def add(a: int, b: int) -> int:
    return a + b


def load_key() -> str:
    return os.environ["API_KEY"]
"""


@pytest.fixture
def settings() -> main.Settings:
    return main.Settings(
        environment="test",
        log_json=False,
        github_webhook_secret=WEBHOOK_SECRET,
        webhook_allowed_repos=[],
    )


@pytest.fixture
def app(settings: main.Settings):
    return main.create_app(settings)


@pytest.fixture
def client(app) -> Iterator[TestClient]:
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def app_factory():
    """Build an app with ad-hoc Settings overrides (test environment by default)."""

    defaults = {"environment": "test", "log_json": False}

    def _factory(**overrides: object):
        return main.create_app(main.Settings(**{**defaults, **overrides}))

    return _factory


@pytest.fixture
def make_finding():
    def _factory(category: FindingCategory, *, line: int = 1, severity: Severity = Severity.HIGH) -> Finding:
        from models import AgentName, CodePosition

        return Finding(
            id="test-finding",
            agent=AgentName.SECURITY_SCANNER,
            category=category,
            severity=severity,
            title="test finding",
            detail="a synthetic finding for verification tests",
            position=CodePosition(line=line),
        )

    return _factory
