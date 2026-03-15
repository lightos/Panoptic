"""Shared data models for Panoptic."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from dataclasses import replace as _dc_replace
from datetime import datetime
from enum import Enum
from typing import Any


class FileType(Enum):
    """Type of file being tested."""

    CONF = "conf"
    LOG = "log"
    OTHER = "other"
    MIX = "mix"


class OutputFormat(Enum):
    """Output format for scan results."""

    TEXT = "text"
    JSON = "json"
    CSV = "csv"


@dataclass(frozen=True)
class Case:
    """A single file path to test. Immutable and hashable."""

    location: str
    os: str | None = None
    category: str | None = None
    software: str | None = None
    file_type: FileType | None = None

    @property
    def case_id(self) -> str:
        """Deterministic identifier for resume/checkpoint.

        Uses SHA-256 instead of Python's hash() which is randomized
        per-process (PEP 456).
        """
        canonical = f"{self.location}|{self.os}|{self.category}|{self.software}|{self.file_type}"
        return hashlib.sha256(canonical.encode()).hexdigest()[:16]


@dataclass
class ScanResult:
    """Result of testing a single case."""

    case: Case
    found: bool
    url: str
    status_code: int | None = None
    content: str | None = None
    content_length: int | None = None
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class ScanConfig:
    """All configuration for a scan. Replaces global args + kb."""

    def __post_init__(self) -> None:
        if self.concurrency < 1:
            raise ValueError(f"concurrency must be >= 1, got {self.concurrency}")
        if not (0.0 < self.heuristic_ratio < 1.0):
            raise ValueError(f"heuristic_ratio must be between 0 and 1 (exclusive), got {self.heuristic_ratio}")
        if self.timeout <= 0:
            raise ValueError(f"timeout must be > 0, got {self.timeout}")
        if self.delay < 0:
            raise ValueError(f"delay must be >= 0, got {self.delay}")
        if self.random_delay is not None:
            if self.random_delay[0] < 0 or self.random_delay[1] < 0:
                raise ValueError("random_delay values must be non-negative")
            if self.random_delay[0] >= self.random_delay[1]:
                raise ValueError("random_delay min must be < max")

    def replace(self, **overrides: Any) -> ScanConfig:
        """Return a copy of this config with the given fields overridden."""
        return _dc_replace(self, **overrides)

    # Target
    url: str
    param: str | None = None
    data: str | None = None
    path_based: bool = False
    prefix: str = ""
    postfix: str = ""
    multiplier: int = 1
    ext_param: str | None = None
    # Performance
    concurrency: int = 4
    timeout: float = 10.0
    retries: int = 3
    delay: float = 0.0
    random_delay: tuple[float, float] | None = None
    # Detection
    bad_string: str | None = None
    replace_slash: str | None = None
    base64_encode: bool = False
    heuristic_ratio: float = 0.9
    # Behavior
    write_files: bool = False
    skip_parsing: bool = False
    automatic: bool = False
    invalid_ssl: bool = False
    all_versions: bool = False
    follow_redirects: bool = False
    # Output
    output_format: OutputFormat = OutputFormat.TEXT
    output_file: str | None = None
    log_file: str | None = None
    verbose: bool = False
    quiet: bool = False
    # Proxy
    proxy: str | None = None
    ignore_proxy: bool = False
    # HTTP headers
    user_agent: str | None = None
    random_agent: bool = False
    cookie: str | None = None
    header: str | None = None
    # Filtering
    os_filter: str | None = None
    software_filter: str | None = None
    category_filter: str | None = None
    type_filter: str | None = None
    # Custom list
    list_file: str | None = None
    # Resume
    resume_file: str | None = None
