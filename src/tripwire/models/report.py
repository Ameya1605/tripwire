"""Report and Diff result models, including risk scoring and MITRE ATT&CK mappings."""

from enum import Enum
from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field


class RiskSeverity(str, Enum):
    CRITICAL = "CRITICAL"  # 9.0 - 10.0 (Honeytoken tripped, shell reverse payload)
    HIGH = "HIGH"          # 7.0 - 8.9 (New outbound network, sensitive file read)
    MEDIUM = "MEDIUM"      # 4.0 - 6.9 (New shell invocation, unusual file drop)
    LOW = "LOW"            # 1.5 - 3.9 (Minor delta, new non-standard file reads)
    BENIGN = "BENIGN"      # 0.0 - 1.4 (Normal compilation / package build variance)


class HoneytokenTrip(BaseModel):
    """Event recording access to a decoy asset."""
    token_id: str
    token_name: str
    token_type: str  # AWS, SSH, NPM, ENV
    accessed_target: str
    pid: int
    process_binary: str
    timestamp: str
    evidence_snippet: str


class BehavioralDelta(BaseModel):
    """Specific behavioral difference between version A and version B."""
    category: str  # file, process, network, honeytoken
    severity: RiskSeverity
    summary: str
    detail: str
    old_state: Optional[str] = None
    new_state: Optional[str] = None
    mitre_attack_id: Optional[str] = None
    mitre_attack_technique: Optional[str] = None


class MITREMapping(BaseModel):
    technique_id: str
    technique_name: str
    tactic: str
    confidence: str = "High"


class DiffResult(BaseModel):
    """Overall result of differential dynamic analysis for a package update."""
    package_name: str
    old_version: str
    new_version: str
    scan_timestamp: str
    duration_sec: float = 0.0

    # Risk metrics
    risk_score: float = 0.0  # 0.0 to 10.0
    severity: RiskSeverity = RiskSeverity.BENIGN
    verdict: str = "PASS"  # PASS, WARN, BLOCK

    # Behavioral findings
    honeytoken_trips: List[HoneytokenTrip] = Field(default_factory=list)
    deltas: List[BehavioralDelta] = Field(default_factory=list)
    mitre_mappings: List[MITREMapping] = Field(default_factory=list)

    # Statistical summary
    old_syscall_count: int = 0
    new_syscall_count: int = 0
    raw_delta_noise_filtered: int = 0  # Number of non-deterministic syscalls normalized out
    meaningful_anomalies_count: int = 0

    executive_summary: str = ""
    markdown_report: str = ""


class PackageAuditItem(BaseModel):
    package_name: str
    old_version: str
    new_version: str
    diff_result: Optional[DiffResult] = None
    status: str = "pending"  # pending, completed, error
    error_message: Optional[str] = None


class AuditSummary(BaseModel):
    manifest_path: str
    total_packages_checked: int = 0
    clean_packages: int = 0
    warn_packages: int = 0
    blocked_packages: int = 0
    highest_risk_score: float = 0.0
    packages: List[PackageAuditItem] = Field(default_factory=list)
