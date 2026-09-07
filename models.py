"""Domain model: constants, enums, Pydantic schemas, and the error hierarchy.

This module has no framework dependencies beyond Pydantic so it can be imported
and unit-tested in isolation.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any, Final, Literal

from pydantic import BaseModel, ConfigDict, Field

# ===========================================================================
# Constants
# ===========================================================================

SERVICE_NAME: Final[str] = "devsecops-automation-engine"
SERVICE_VERSION: Final[str] = "2.0.0"
API_V1_PREFIX: Final[str] = "/api/v1"
REQUEST_ID_HEADER: Final[str] = "X-Request-ID"
MAX_SOURCE_BYTES: Final[int] = 512 * 1024  # 512 KiB hard limit on analysed code
MAX_REGEX_LINE: Final[int] = 4_000  # lines longer than this skip expensive regex (ReDoS guard)
LLM_CONTEXT_RADIUS: Final[int] = 6  # source lines of context sent around a finding
MAX_PATCH_CHARS: Final[int] = 8_000  # bound on any single remediation patch body

# Starlette renamed several status constants across versions; use the numbers.
HTTP_400_BAD_REQUEST: Final[int] = 400
HTTP_401_UNAUTHORIZED: Final[int] = 401
HTTP_404_NOT_FOUND: Final[int] = 404
HTTP_413_TOO_LARGE: Final[int] = 413
HTTP_422_UNPROCESSABLE: Final[int] = 422
HTTP_500_INTERNAL: Final[int] = 500
HTTP_502_BAD_GATEWAY: Final[int] = 502
HTTP_503_UNAVAILABLE: Final[int] = 503
HTTP_504_GATEWAY_TIMEOUT: Final[int] = 504

# Hosts the webhook processor is permitted to fetch from (SSRF allow-list).
ALLOWED_GITHUB_HOSTS: Final[frozenset[str]] = frozenset(
    {
        "api.github.com",
        "raw.githubusercontent.com",
        "github.com",
        "objects.githubusercontent.com",
        "codeload.github.com",
    }
)
PR_ACTIONS_TO_ANALYZE: Final[frozenset[str]] = frozenset(
    {"opened", "synchronize", "reopened", "ready_for_review"}
)
DOC_PATHS: Final[frozenset[str]] = frozenset({"/docs", "/redoc", "/openapi.json", "/docs/oauth2-redirect"})


def utcnow() -> datetime:
    """Timezone-aware UTC now (``datetime.utcnow`` is deprecated in 3.12+)."""

    return datetime.now(UTC)


# ===========================================================================
# Enums
# ===========================================================================


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK: Final[dict[Severity, int]] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class FindingCategory(str, Enum):
    SYNTAX = "syntax"
    PERFORMANCE = "performance"
    DANGEROUS_CALL = "dangerous_call"
    HARDCODED_SECRET = "hardcoded_secret"
    SQL_INJECTION = "sql_injection"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    INSECURE_DESERIALIZATION = "insecure_deserialization"
    WEAK_CRYPTO = "weak_crypto"
    WEAK_PASSWORD_HASH = "weak_password_hash"
    INSECURE_TRANSPORT = "insecure_transport"
    SSRF = "ssrf"
    SECURITY_MISCONFIG = "security_misconfig"
    STYLE = "style"


class AgentName(str, Enum):
    AST_STRUCTURAL = "ast_structural_parser"
    SECURITY_SCANNER = "security_pattern_scanner"
    REMEDIATION = "remediation_generator"


class AgentStatus(str, Enum):
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"


class ValidationStatus(str, Enum):
    """Outcome of verifying a generated patch."""

    VALIDATED = "validated"  # parses AND the original finding no longer fires
    UNRESOLVED = "unresolved"  # parses but the finding still fires against the patch
    REJECTED = "rejected"  # patch is not valid / looks truncated
    NOT_CHECKED = "not_checked"  # verification did not apply to this patch type


class PatchType(str, Enum):
    SNIPPET = "snippet"  # a concrete code replacement that can be re-scanned
    GUIDANCE = "guidance"  # advisory text / illustrative example, not re-scannable


RemediationSource = Literal["llm", "template"]
RemediationMode = Literal["llm", "template", "mixed", "none"]


# ===========================================================================
# Schemas
# ===========================================================================


class _Schema(BaseModel):
    """Base schema: forbid unknown fields, freeze on the wire."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class CodePosition(_Schema):
    line: int = Field(ge=1)
    column: int | None = Field(default=None, ge=0)


class Finding(_Schema):
    id: str
    agent: AgentName
    category: FindingCategory
    severity: Severity
    title: str = Field(min_length=3, max_length=160)
    detail: str = Field(min_length=3, max_length=2_000)
    position: CodePosition | None = None
    remediation_hint: str | None = Field(default=None, max_length=2_000)
    evidence: str | None = Field(default=None, max_length=400, description="Redacted supporting snippet.")


class AgentReport(_Schema):
    agent: AgentName
    status: AgentStatus
    started_at: datetime
    finished_at: datetime
    duration_ms: float = Field(ge=0)
    findings: tuple[Finding, ...] = ()
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.status is AgentStatus.COMPLETED


class PatchValidation(_Schema):
    """Result of the FINDING → PATCH → VALIDATE → RE-SCAN → VERDICT loop."""

    status: ValidationStatus
    parsed_ok: bool
    finding_resolved: bool | None = None
    errors: tuple[str, ...] = ()
    residual_categories: tuple[FindingCategory, ...] = ()


class RemediationPatch(_Schema):
    target_finding_id: str
    category: FindingCategory
    patch_type: PatchType
    summary: str = Field(min_length=3, max_length=200)
    rationale: str = Field(min_length=3, max_length=2_000)
    original_snippet: str | None = Field(default=None, max_length=MAX_PATCH_CHARS)
    suggested_code: str = Field(min_length=1, max_length=MAX_PATCH_CHARS)
    unified_diff: str | None = Field(default=None, max_length=2 * MAX_PATCH_CHARS)
    confidence: float = Field(ge=0.0, le=1.0)
    source: RemediationSource = "template"
    provider: str | None = None
    model: str | None = None
    validation: PatchValidation


class AnalyzeRequest(_Schema):
    filename: str = Field(default="submission.py", max_length=255)
    language: str = Field(default="python")
    source_code: str = Field(min_length=1, description=f"UTF-8 source, max {MAX_SOURCE_BYTES} bytes.")
    enable_remediation: bool = Field(default=True)


class PipelineMetrics(_Schema):
    total_findings: int = Field(ge=0)
    by_severity: dict[Severity, int]
    by_category: dict[FindingCategory, int]
    highest_severity: Severity
    agents_succeeded: int = Field(ge=0)
    agents_failed: int = Field(ge=0)


class AnalyzeResponse(_Schema):
    analysis_id: str
    filename: str
    created_at: datetime
    duration_ms: float = Field(ge=0)
    gate_passed: bool = Field(description="False when any finding is HIGH severity or above.")
    remediation_mode: RemediationMode
    stored: bool = False
    metrics: PipelineMetrics
    agent_reports: tuple[AgentReport, ...]
    findings: tuple[Finding, ...]
    patches: tuple[RemediationPatch, ...]


class AnalysisSummary(_Schema):
    analysis_id: str
    filename: str
    created_at: datetime
    gate_passed: bool
    total_findings: int
    highest_severity: Severity
    remediation_mode: RemediationMode


class AnalysisListResponse(_Schema):
    count: int
    analyses: tuple[AnalysisSummary, ...]


class WebhookFileResult(_Schema):
    filename: str
    analyzed: bool
    analysis_id: str | None = None
    gate_passed: bool | None = None
    total_findings: int | None = None
    highest_severity: Severity | None = None
    error: str | None = None


class WebhookDelivery(_Schema):
    delivery_id: str
    event: str
    repository: str
    ref: str
    sha: str
    received_at: datetime
    completed_at: datetime
    gate_passed: bool
    files: tuple[WebhookFileResult, ...]


class WebhookAcceptedResponse(_Schema):
    delivery_id: str
    event: str
    repository: str | None = None
    ref: str | None = None
    accepted: bool
    queued_files: tuple[str, ...] = ()
    skipped: tuple[str, ...] = ()
    note: str | None = None


class WebhookDeliveriesResponse(_Schema):
    count: int
    deliveries: tuple[WebhookDelivery, ...]


class HealthResponse(_Schema):
    status: str
    service: str
    version: str
    environment: str
    time: datetime
    active_pipelines: int
    log_subscribers: int
    llm_provider: str
    llm_live: bool
    webhook_enabled: bool
    persistence_enabled: bool


class ErrorResponse(_Schema):
    error: str
    message: str
    request_id: str | None = None
    detail: Any | None = None


# ===========================================================================
# Exception hierarchy
# ===========================================================================


class EngineError(Exception):
    """Base class for all deliberately raised application errors."""

    status_code: int = HTTP_500_INTERNAL
    error_code: str = "engine_error"

    def __init__(self, message: str, *, detail: Any | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.detail = detail


class InvalidSubmissionError(EngineError):
    status_code = HTTP_422_UNPROCESSABLE
    error_code = "invalid_submission"


class PipelineTimeoutError(EngineError):
    status_code = HTTP_504_GATEWAY_TIMEOUT
    error_code = "pipeline_timeout"


class PipelineOverloadedError(EngineError):
    status_code = HTTP_503_UNAVAILABLE
    error_code = "pipeline_overloaded"


class FeatureDisabledError(EngineError):
    status_code = HTTP_503_UNAVAILABLE
    error_code = "feature_disabled"


class ResourceNotFoundError(EngineError):
    status_code = HTTP_404_NOT_FOUND
    error_code = "not_found"


class WebhookError(EngineError):
    status_code = HTTP_400_BAD_REQUEST
    error_code = "webhook_invalid"


class WebhookAuthError(EngineError):
    status_code = HTTP_401_UNAUTHORIZED
    error_code = "webhook_unauthorized"


class UpstreamFetchError(EngineError):
    status_code = HTTP_502_BAD_GATEWAY
    error_code = "upstream_fetch_failed"
