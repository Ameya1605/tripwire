"""Honeytoken Generation and Active Deception Subsystem for Tripwire."""

import os
import uuid
import hashlib
from typing import Dict, List, Set, Optional, Tuple
from pathlib import Path
from tripwire.models.report import HoneytokenTrip


class HoneytokenManager:
    """
    Manages the lifecycle of active honeytoken deception assets inside
    the detonation sandbox, including filesystem canaries and decoy env vars.
    """

    SENSITIVE_TARGETS: Dict[str, str] = {
        ".aws/credentials": "AWS Credentials File",
        ".aws/config": "AWS Configuration File",
        ".ssh/id_rsa": "SSH RSA Private Key",
        ".ssh/id_ed25519": "SSH Ed25519 Private Key",
        ".npmrc": "NPM Authentication RC File",
        ".kube/config": "Kubernetes Cluster Config",
        "/etc/shadow": "System Shadow Passwords",
        "/etc/passwd": "System User Account Database",
        ".env": "Environment Secrets File",
    }

    DECOY_ENV_KEYS: List[str] = [
        "AWS_SECRET_ACCESS_KEY",
        "AWS_ACCESS_KEY_ID",
        "NPM_TOKEN",
        "GITHUB_TOKEN",
        "SLACK_WEBHOOK_URL",
        "DATABASE_URL",
    ]

    def __init__(self, seed: Optional[str] = None):
        self.session_id = seed or uuid.uuid4().hex[:8]
        self.canary_id = f"TW-{self.session_id.upper()}"
        self.canary_hash = hashlib.sha256(self.session_id.encode()).hexdigest()[:16]
        
        # In-memory tracking of all generated canary substrings
        self.tracked_canaries: Set[str] = {
            self.canary_id,
            self.canary_hash,
            f"AKIA_TRIPWIRE_CANARY_{self.canary_id}",
            f"tripwire_secret_canary_key_{self.canary_hash}",
            f"npm_canary_tripwire_{self.canary_id}_{self.canary_hash}",
        }
        
        self.env_honeytokens: Dict[str, str] = {
            "AWS_ACCESS_KEY_ID": f"AKIA_TRIPWIRE_CANARY_{self.canary_id}",
            "AWS_SECRET_ACCESS_KEY": f"tripwire_secret_canary_key_{self.canary_hash}",
            "NPM_TOKEN": f"npm_canary_tripwire_{self.canary_id}_{self.canary_hash}",
            "GITHUB_TOKEN": f"ghp_tripwireCanaryDecoy_{self.canary_hash}",
            "SLACK_WEBHOOK_URL": f"https://hooks.slack.com/services/T00/B00/canary_{self.canary_hash}",
        }

    def prepare_sandbox_honeytokens(self, output_dir: Path) -> Dict[str, Path]:
        """
        Renders template honeytoken files into a temporary directory
        to be volume-mounted into the detonation container.
        """
        output_dir.mkdir(parents=True, exist_ok=True)
        rendered_files = {}

        # Render AWS Credentials
        aws_content = f"""[default]
aws_access_key_id = AKIA_TRIPWIRE_CANARY_{self.canary_id}
aws_secret_access_key = tripwire_secret_canary_key_{self.canary_hash}
region = us-east-1
"""
        aws_path = output_dir / "aws_credentials"
        aws_path.write_text(aws_content)
        rendered_files["aws"] = aws_path

        # Render SSH ID_RSA
        ssh_content = f"""-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAuCANARY_TRIPWIRE_SSH_{self.canary_id}_DUMMY_KEY_PAYLOAD
AAAAwEAAQAAAYEAuTRIPWIRE_SECRET_CANARY_CANARY_KEY_SIGNATURE_{self.canary_hash}
-----END OPENSSH PRIVATE KEY-----
"""
        ssh_path = output_dir / "id_rsa"
        ssh_path.write_text(ssh_content)
        rendered_files["ssh"] = ssh_path

        # Render NPMRC
        npmrc_content = f"//registry.npmjs.org/:_authToken=npm_canary_tripwire_{self.canary_id}_{self.canary_hash}\n"
        npmrc_path = output_dir / "npmrc"
        npmrc_path.write_text(npmrc_content)
        rendered_files["npmrc"] = npmrc_path

        # Render Kube Config
        kube_content = f"""apiVersion: v1
clusters:
- cluster:
    server: https://canary-k8s-cluster.internal.tripwire:6443
  name: canary-cluster-{self.canary_id}
contexts:
- context:
    cluster: canary-cluster-{self.canary_id}
    user: canary-user-{self.canary_id}
  name: canary-context
current-context: canary-context
kind: Config
preferences: {{}}
users:
- user:
    token: canary-jwt-token-{self.canary_id}-{self.canary_hash}
  name: canary-user-{self.canary_id}
"""
        kube_path = output_dir / "kube_config"
        kube_path.write_text(kube_content)
        rendered_files["kube"] = kube_path

        return rendered_files

    def evaluate_file_access(self, file_path: str, pid: int = 0, process: str = "unknown", timestamp: str = "") -> Optional[HoneytokenTrip]:
        """
        Evaluates whether an accessed file matches a honeytoken decoy asset.
        """
        normalized = file_path.replace("\\", "/")
        for sensitive_suffix, token_name in self.SENSITIVE_TARGETS.items():
            if normalized.endswith(sensitive_suffix):
                token_type = "AWS" if "aws" in sensitive_suffix else ("SSH" if "ssh" in sensitive_suffix else ("NPM" if "npm" in sensitive_suffix else "SYSTEM"))
                return HoneytokenTrip(
                    token_id=self.canary_id,
                    token_name=token_name,
                    token_type=token_type,
                    accessed_target=file_path,
                    pid=pid,
                    process_binary=process,
                    timestamp=timestamp,
                    evidence_snippet=f"File access detected to honeytoken asset: {file_path}",
                )
        return None

    def evaluate_payload_leak(self, data_str: str, pid: int = 0, process: str = "unknown", timestamp: str = "") -> Optional[HoneytokenTrip]:
        """
        Scans network payload or string buffer for presence of canary hashes.
        """
        for canary in self.tracked_canaries:
            if canary in data_str:
                return HoneytokenTrip(
                    token_id=self.canary_id,
                    token_name="Canary Cryptographic Hash",
                    token_type="EXFILTRATION",
                    accessed_target="Canary String Leak",
                    pid=pid,
                    process_binary=process,
                    timestamp=timestamp,
                    evidence_snippet=f"Canary string signature '{canary}' detected in payload/command buffer.",
                )
        return None

    def evaluate_env_access(self, env_var: str, pid: int = 0, process: str = "unknown", timestamp: str = "") -> Optional[HoneytokenTrip]:
        """
        Evaluates whether an accessed environment variable is a honeytoken decoy.
        """
        if env_var in self.DECOY_ENV_KEYS:
            return HoneytokenTrip(
                token_id=self.canary_id,
                token_name=f"Decoy Env Variable ({env_var})",
                token_type="ENV",
                accessed_target=env_var,
                pid=pid,
                process_binary=process,
                timestamp=timestamp,
                evidence_snippet=f"Environment variable probe detected for honeytoken key: {env_var}",
            )
        return None
