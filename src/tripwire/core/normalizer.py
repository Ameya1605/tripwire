"""Deterministic Trace Normalization and Canonicalization Engine for Tripwire."""

import re
import hashlib
from typing import List, Dict, Set, Optional
from tripwire.models.telemetry import FileOpEvent, ProcessEvent, NetworkEvent, FileOpType
from tripwire.models.fingerprint import (
    CanonicalFileAction,
    CanonicalProcessNode,
    CanonicalNetworkTarget,
    CanonicalBehaviorFingerprint,
)
from tripwire.core.tracer import SyscallTracer
from tripwire.core.honeytokens import HoneytokenManager


class TraceNormalizer:
    """
    Normalizes raw execution traces into deterministic canonical fingerprints.
    Filters out non-deterministic noise (PIDs, timestamps, temp dirs, ASLR offsets,
    transient library probes) so that identical package behaviors yield identical fingerprints.
    """

    # Regex patterns for dynamic path scrubbing
    RE_TMP_NPM = re.compile(r"/tmp/npm-[a-zA-Z0-9_\-\.]+", re.IGNORECASE)
    RE_TMP_RANDOM = re.compile(r"/tmp/[a-zA-Z0-9_\-\.]{8,}", re.IGNORECASE)
    RE_PROC_PID = re.compile(r"/proc/\d+", re.IGNORECASE)
    RE_HEX_MEM = re.compile(r"0x[0-9a-fA-F]{6,}")
    RE_TMP_V8 = re.compile(r"/tmp/v8-compile-cache-\d+", re.IGNORECASE)

    # Benign system library paths to collapse (low-signal glibc / node internals)
    SYSTEM_LIB_PREFIXES = (
        "/etc/ld.so.",
        "/lib/x86_64-linux-gnu/",
        "/usr/lib/x86_64-linux-gnu/",
        "/lib64/",
        "/usr/local/include/node/",
    )

    def __init__(self, honeytokens: Optional[HoneytokenManager] = None):
        self.honeytokens = honeytokens or HoneytokenManager()

    def normalize_path(self, path: str) -> str:
        """Transforms variable system and ephemeral paths into deterministic tokens."""
        if not path:
            return ""

        # Normalize slashes
        clean_path = path.replace("\\", "/")

        # Check for system library lookup collapse
        for prefix in self.SYSTEM_LIB_PREFIXES:
            if clean_path.startswith(prefix):
                return "<SYS_GLIBC_LOADER>"

        # Replace dynamic temp directories
        clean_path = self.RE_TMP_NPM.sub("<TMP_NPM>", clean_path)
        clean_path = self.RE_TMP_V8.sub("<TMP_V8_CACHE>", clean_path)
        clean_path = self.RE_TMP_RANDOM.sub("<TMP_EPHEMERAL>", clean_path)
        clean_path = self.RE_PROC_PID.sub("/proc/<PID>", clean_path)

        # Canonicalize user and app workspace paths
        clean_path = clean_path.replace("/home/sandbox-runner", "<HOME>")
        clean_path = clean_path.replace("/detonation/node_modules", "<NODE_MODULES>")
        clean_path = clean_path.replace("/detonation", "<APP_DIR>")
        clean_path = clean_path.replace("/usr/local/lib/node_modules", "<GLOBAL_NODE_MODULES>")

        return clean_path

    def normalize_command(self, argv: List[str]) -> str:
        """Canonicalizes process execution argument vectors."""
        if not argv:
            return ""
        norm_tokens = []
        for token in argv:
            norm = self.normalize_path(token)
            # Normalize node binary invocation
            if norm.endswith("/node") or norm == "node":
                norm = "node"
            norm_tokens.append(norm)
        return " ".join(norm_tokens)

    def canonicalize_trace(
        self,
        tracer: SyscallTracer,
        pkg_name: str,
        version: str,
        duration_sec: float = 0.0,
    ) -> CanonicalBehaviorFingerprint:
        """
        Processes all parsed telemetry from SyscallTracer into a CanonicalBehaviorFingerprint.
        """
        file_actions: Dict[str, CanonicalFileAction] = {}
        process_commands: List[str] = []
        network_targets: Dict[str, CanonicalNetworkTarget] = {}
        env_vars_read: Set[str] = set()

        # 1. Process and normalize file actions
        for file_ev in tracer.file_events:
            norm_path = self.normalize_path(file_ev.raw_path)
            if not norm_path or norm_path == "<SYS_GLIBC_LOADER>":
                continue  # Discard low-signal loader probes

            # Determine action verb
            action = file_ev.op_type.value.upper()
            key = f"{action}:{norm_path}"

            is_sensitive = any(
                sens in norm_path for sens in [".aws", ".ssh", ".npmrc", ".kube", "/etc/shadow", "/etc/passwd", ".env"]
            )
            is_honey = bool(self.honeytokens.evaluate_file_access(file_ev.raw_path))

            if key in file_actions:
                file_actions[key].count += 1
            else:
                file_actions[key] = CanonicalFileAction(
                    normalized_path=norm_path,
                    action=action,
                    is_sensitive=is_sensitive,
                    is_honeytoken=is_honey,
                    count=1,
                )

        # 2. Process and normalize process executions
        seen_cmds = set()
        for proc_ev in tracer.process_events:
            norm_cmd = self.normalize_command(proc_ev.argv if proc_ev.argv else [proc_ev.binary])
            if norm_cmd and norm_cmd not in seen_cmds:
                seen_cmds.add(norm_cmd)
                process_commands.append(norm_cmd)

        # 3. Process and normalize network connections
        for net_ev in tracer.network_events:
            if net_ev.is_loopback:
                continue  # Ignore local IPC / loopback
            target = net_ev.ip or net_ev.domain or "unknown"
            key = f"{net_ev.family}:{target}:{net_ev.port}"
            if key not in network_targets:
                network_targets[key] = CanonicalNetworkTarget(
                    family=net_ev.family,
                    target=target,
                    port=net_ev.port,
                    is_external=not net_ev.is_loopback,
                )

        # 4. Generate deterministic cryptographic invariant hash
        hasher = hashlib.sha256()
        for key in sorted(file_actions.keys()):
            hasher.update(key.encode())
        for cmd in sorted(process_commands):
            hasher.update(cmd.encode())
        for net_k in sorted(network_targets.keys()):
            hasher.update(net_k.encode())

        fingerprint_hash = hasher.hexdigest()

        return CanonicalBehaviorFingerprint(
            package_name=pkg_name,
            version=version,
            total_syscalls=len(tracer.raw_records),
            duration_sec=duration_sec,
            file_actions=file_actions,
            process_commands=process_commands,
            network_targets=network_targets,
            env_vars_read=env_vars_read,
            fingerprint_hash=fingerprint_hash,
        )
