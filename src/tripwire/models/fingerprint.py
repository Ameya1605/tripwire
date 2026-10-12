"""Canonical behavior fingerprint models for baseline profiling and diffing."""

from typing import List, Dict, Set, Optional, Any
from pydantic import BaseModel, Field


class CanonicalFileAction(BaseModel):
    """Canonicalized file operation invariant."""
    normalized_path: str
    action: str  # READ, WRITE, UNLINK, CHMOD
    is_sensitive: bool = False
    is_honeytoken: bool = False
    count: int = 1

    def to_key(self) -> str:
        return f"{self.action}:{self.normalized_path}"


class CanonicalProcessNode(BaseModel):
    """Canonicalized process tree node."""
    normalized_binary: str
    normalized_cmd: str
    depth: int = 0
    is_shell: bool = False
    is_network_tool: bool = False
    children: List["CanonicalProcessNode"] = Field(default_factory=list)

    def to_key(self) -> str:
        return f"EXEC:{self.normalized_cmd}"


class CanonicalNetworkTarget(BaseModel):
    """Canonicalized network connection destination."""
    family: str
    target: str  # IP or domain
    port: Optional[int] = None
    is_external: bool = True

    def to_key(self) -> str:
        return f"{self.family}:{self.target}:{self.port or '*'}"


class CanonicalBehaviorFingerprint(BaseModel):
    """
    Complete behavioral profile for a package version.
    This acts as the empirical baseline for differential analysis.
    """
    package_name: str
    version: str
    total_syscalls: int
    duration_sec: float = 0.0

    # Categorized canonical event sets
    file_actions: Dict[str, CanonicalFileAction] = Field(default_factory=dict)
    process_commands: List[str] = Field(default_factory=list)
    process_tree: List[CanonicalProcessNode] = Field(default_factory=list)
    network_targets: Dict[str, CanonicalNetworkTarget] = Field(default_factory=dict)
    env_vars_read: Set[str] = Field(default_factory=set)

    # Invariant cryptographic hash of canonical behavior
    fingerprint_hash: str = ""
