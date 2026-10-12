"""Differential Behavioral Diff Engine (DDBA) for Tripwire."""

from typing import List, Dict, Set, Optional
from datetime import datetime, timezone
from tripwire.models.fingerprint import CanonicalBehaviorFingerprint
from tripwire.models.report import (
    DiffResult,
    BehavioralDelta,
    RiskSeverity,
    HoneytokenTrip,
)
from tripwire.core.honeytokens import HoneytokenManager


class BehavioralDiffEngine:
    """
    Computes the differential behavioral delta between two canonical fingerprints:
    ΔB = B(v_new) ⊖ B(v_old)
    Legitimate baseline behaviors present in the previous release are suppressed,
    while novel execution anomalies are isolated and highlighted.
    """

    def __init__(self, honeytokens: Optional[HoneytokenManager] = None):
        self.honeytokens = honeytokens or HoneytokenManager()

    def diff(
        self,
        old_fp: CanonicalBehaviorFingerprint,
        new_fp: CanonicalBehaviorFingerprint,
        honeytoken_trips: Optional[List[HoneytokenTrip]] = None,
    ) -> DiffResult:
        """
        Executes differential comparison between old_fp and new_fp.
        """
        trips = list(honeytoken_trips or [])
        deltas: List[BehavioralDelta] = []

        # 1. Evaluate Honeytokens
        for trip in trips:
            deltas.append(
                BehavioralDelta(
                    category="honeytoken",
                    severity=RiskSeverity.CRITICAL,
                    summary=f"Honeytoken Decoy Breached: {trip.token_name}",
                    detail=f"Process '{trip.process_binary}' (PID {trip.pid}) accessed decoy target '{trip.accessed_target}'. Evidence: {trip.evidence_snippet}",
                    old_state="Untouched",
                    new_state=f"Accessed by {trip.process_binary}",
                    mitre_attack_id="T1552.001",
                    mitre_attack_technique="Credentials In Files",
                )
            )

        # 2. Differential File Operations Delta (ΔF = F_new - F_old)
        old_file_keys = set(old_fp.file_actions.keys())
        for key, new_action in new_fp.file_actions.items():
            if key not in old_file_keys:
                # This file action is NOVEL to the new version
                norm_path = new_action.normalized_path
                
                # Check for sensitive target access
                if new_action.is_sensitive:
                    severity = RiskSeverity.HIGH if new_action.action == "READ" else RiskSeverity.CRITICAL
                    deltas.append(
                        BehavioralDelta(
                            category="file",
                            severity=severity,
                            summary=f"Novel Sensitive File {new_action.action}: {norm_path}",
                            detail=f"Version {new_fp.version} initiated novel {new_action.action} on sensitive path '{norm_path}' which was never touched in {old_fp.version}.",
                            old_state="Not accessed",
                            new_state=f"{new_action.action} ({new_action.count} ops)",
                            mitre_attack_id="T1552.001",
                            mitre_attack_technique="Credentials In Files",
                        )
                    )
                elif new_action.action in ["WRITE", "UNLINK"] and not norm_path.startswith(("<NODE_MODULES>", "<TMP_NPM>")):
                    is_home_or_root = norm_path.startswith(("<HOME>", "/etc", "/root"))
                    sev = RiskSeverity.HIGH if is_home_or_root else RiskSeverity.MEDIUM
                    deltas.append(
                        BehavioralDelta(
                            category="file",
                            severity=sev,
                            summary=f"Novel External File Mutation: {norm_path}",
                            detail=f"Version {new_fp.version} performed novel {new_action.action} outside project directory ('{norm_path}').",
                            old_state="Not touched",
                            new_state=f"{new_action.action} ({new_action.count} ops)",
                            mitre_attack_id="T1485" if is_home_or_root else "T1070",
                            mitre_attack_technique="Data Destruction / Host Sabotage" if is_home_or_root else "File Modification",
                        )
                    )
                elif norm_path.startswith("<HOME>") or norm_path.startswith("/etc"):
                    deltas.append(
                        BehavioralDelta(
                            category="file",
                            severity=RiskSeverity.MEDIUM,
                            summary=f"Novel Non-Local File {new_action.action}: {norm_path}",
                            detail=f"Version {new_fp.version} accessed filesystem outside project boundary: '{norm_path}'.",
                            old_state="Not accessed",
                            new_state=f"{new_action.action} ({new_action.count} ops)",
                            mitre_attack_id="T1083",
                            mitre_attack_technique="File and Directory Discovery",
                        )
                    )

        # 3. Differential Process Execution Delta (ΔP = P_new - P_old)
        old_cmds = set(old_fp.process_commands)
        for new_cmd in new_fp.process_commands:
            if new_cmd not in old_cmds:
                # Check if command spawns shell or network utility
                tokens = new_cmd.split()
                bin_name = tokens[0].split("/")[-1] if tokens else ""
                
                if bin_name in {"sh", "bash", "dash", "ash", "zsh"}:
                    deltas.append(
                        BehavioralDelta(
                            category="process",
                            severity=RiskSeverity.HIGH,
                            summary=f"Novel Shell Execution Spawned: {bin_name}",
                            detail=f"Version {new_fp.version} spawned command shell '{new_cmd}'. Previous version {old_fp.version} executed no shell subprocess.",
                            old_state="No shell execution",
                            new_state=new_cmd,
                            mitre_attack_id="T1059.004",
                            mitre_attack_technique="Command and Scripting Interpreter: Unix Shell",
                        )
                    )
                elif bin_name in {"curl", "wget", "nc", "python", "python3"}:
                    deltas.append(
                        BehavioralDelta(
                            category="process",
                            severity=RiskSeverity.HIGH,
                            summary=f"Novel External Tool Executed: {bin_name}",
                            detail=f"Version {new_fp.version} executed binary utility '{new_cmd}'.",
                            old_state="Not executed",
                            new_state=new_cmd,
                            mitre_attack_id="T1105",
                            mitre_attack_technique="Ingress Tool Transfer",
                        )
                    )
                else:
                    deltas.append(
                        BehavioralDelta(
                            category="process",
                            severity=RiskSeverity.LOW,
                            summary=f"Novel Subprocess Invocations: {bin_name}",
                            detail=f"Process invocation delta: '{new_cmd}'.",
                            old_state="Not executed",
                            new_state=new_cmd,
                            mitre_attack_id="T1059",
                            mitre_attack_technique="Command and Scripting Interpreter",
                        )
                    )

        # 4. Differential Network Egress Delta (ΔN = N_new - N_old)
        old_net_keys = set(old_fp.network_targets.keys())
        for net_key, new_net in new_fp.network_targets.items():
            if net_key not in old_net_keys:
                deltas.append(
                    BehavioralDelta(
                        category="network",
                        severity=RiskSeverity.HIGH,
                        summary=f"Novel Outbound Network Egress: {new_net.target}:{new_net.port or '*'}",
                        detail=f"Version {new_fp.version} attempted network socket connection to '{new_net.target}' ({new_net.family}) on port {new_net.port}. Previous version {old_fp.version} initiated zero connections to this target.",
                        old_state="No connection",
                        new_state=f"Connected to {new_net.target}:{new_net.port}",
                        mitre_attack_id="T1071.001",
                        mitre_attack_technique="Application Layer Protocol: Web Protocols",
                    )
                )

        # Compute noise reduction metric
        total_raw_old = old_fp.total_syscalls
        total_raw_new = new_fp.total_syscalls
        raw_diff_estimate = abs(total_raw_new - total_raw_old)
        meaningful_count = len(deltas)
        noise_filtered = max(0, (total_raw_new + total_raw_old) - (len(new_fp.file_actions) + len(old_fp.file_actions)))

        now_str = datetime.now(timezone.utc).isoformat()
        return DiffResult(
            package_name=new_fp.package_name,
            old_version=old_fp.version,
            new_version=new_fp.version,
            scan_timestamp=now_str,
            duration_sec=new_fp.duration_sec + old_fp.duration_sec,
            honeytoken_trips=trips,
            deltas=deltas,
            old_syscall_count=total_raw_old,
            new_syscall_count=total_raw_new,
            raw_delta_noise_filtered=noise_filtered,
            meaningful_anomalies_count=meaningful_count,
        )
