"""Threat Attribution and Risk Scoring Engine for Tripwire."""

from typing import List, Dict, Tuple
from tripwire.models.report import (
    DiffResult,
    RiskSeverity,
    BehavioralDelta,
    MITREMapping,
)


class RiskScorer:
    """
    Evaluates behavioral deltas against supply chain threat heuristics,
    assigns normalized risk scores (0.0 - 10.0), and maps findings to
    MITRE ATT&CK Supply Chain techniques.
    """

    MITRE_CATALOG: Dict[str, Tuple[str, str]] = {
        "T1552.001": ("Credentials In Files", "Credential Access"),
        "T1059.004": ("Command and Scripting Interpreter: Unix Shell", "Execution"),
        "T1071.001": ("Application Layer Protocol: Web Protocols", "Command and Control"),
        "T1567": ("Exfiltration Over Web Service", "Exfiltration"),
        "T1105": ("Ingress Tool Transfer", "Command and Control"),
        "T1083": ("File and Directory Discovery", "Discovery"),
        "T1070": ("Indicator Removal on Host", "Defense Evasion"),
        "T1485": ("Data Destruction", "Impact"),
        "T1496": ("Resource Hijacking", "Impact"),
    }

    def evaluate(self, diff_result: DiffResult) -> DiffResult:
        """
        Calculates composite risk score, severity, verdict, MITRE mappings,
        and generates executive markdown summary.
        """
        score = 0.0
        seen_mitre = set()
        mitre_list: List[MITREMapping] = []

        # 1. Honeytoken Evaluation (Automatic Critical Breach)
        if diff_result.honeytoken_trips:
            score += 10.0
            seen_mitre.add("T1552.001")

        # 2. Behavioral Delta Evaluation
        for delta in diff_result.deltas:
            if delta.category == "honeytoken":
                continue  # Handled above

            if delta.category == "process":
                if delta.severity == RiskSeverity.HIGH:
                    score += 5.0
                    if delta.mitre_attack_id:
                        seen_mitre.add(delta.mitre_attack_id)
                else:
                    score += 1.0

            elif delta.category == "network":
                if delta.severity == RiskSeverity.HIGH:
                    score += 4.0
                    seen_mitre.add("T1071.001")
                    seen_mitre.add("T1567")

            elif delta.category == "file":
                if delta.severity == RiskSeverity.CRITICAL:
                    score += 10.0
                    seen_mitre.add("T1552.001")
                elif delta.severity == RiskSeverity.HIGH:
                    score += 7.0
                    if delta.mitre_attack_id:
                        seen_mitre.add(delta.mitre_attack_id)
                    else:
                        seen_mitre.add("T1552.001")
                elif delta.severity == RiskSeverity.MEDIUM:
                    score += 2.0
                    if delta.mitre_attack_id:
                        seen_mitre.add(delta.mitre_attack_id)

        # Cap score at 10.0
        final_score = min(10.0, round(score, 1))
        diff_result.risk_score = final_score

        # Determine Severity & Gating Verdict
        if final_score >= 9.0:
            diff_result.severity = RiskSeverity.CRITICAL
            diff_result.verdict = "BLOCK"
        elif final_score >= 7.0:
            diff_result.severity = RiskSeverity.HIGH
            diff_result.verdict = "BLOCK"
        elif final_score >= 4.0:
            diff_result.severity = RiskSeverity.MEDIUM
            diff_result.verdict = "WARN"
        elif final_score >= 1.5:
            diff_result.severity = RiskSeverity.LOW
            diff_result.verdict = "PASS"
        else:
            diff_result.severity = RiskSeverity.BENIGN
            diff_result.verdict = "PASS"

        # Populate MITRE ATT&CK Mappings
        for tid in sorted(seen_mitre):
            if tid in self.MITRE_CATALOG:
                name, tactic = self.MITRE_CATALOG[tid]
                mitre_list.append(
                    MITREMapping(technique_id=tid, technique_name=name, tactic=tactic)
                )
        diff_result.mitre_mappings = mitre_list

        # Generate Plain-English Summaries
        diff_result.executive_summary = self._generate_executive_summary(diff_result)
        diff_result.markdown_report = self._generate_markdown_report(diff_result)

        return diff_result

    def _generate_executive_summary(self, res: DiffResult) -> str:
        if res.verdict == "PASS":
            return (
                f"Package update '{res.package_name}' ({res.old_version} -> {res.new_version}) "
                f"exhibits normal release behavior. All {res.new_syscall_count} runtime operations "
                f"align with the verified behavioral baseline."
            )
        
        reasons = []
        if res.honeytoken_trips:
            reasons.append(f"{len(res.honeytoken_trips)} synthetic honeytoken canary assets were breached")
        
        shells = [d for d in res.deltas if d.category == "process" and d.severity == RiskSeverity.HIGH]
        if shells:
            reasons.append(f"unauthorized shell execution was spawned during install ({shells[0].new_state})")

        egress = [d for d in res.deltas if d.category == "network"]
        if egress:
            reasons.append(f"novel outbound network socket was initiated ({egress[0].new_state})")

        files = [d for d in res.deltas if d.category == "file" and d.severity in [RiskSeverity.CRITICAL, RiskSeverity.HIGH]]
        if files:
            reasons.append(f"unauthorized access to sensitive filesystem locations ({files[0].summary})")

        joined = "; ".join(reasons) if reasons else "suspicious behavioral modifications detected"
        return (
            f"SECURITY ALERT [{res.severity.value}]: Package '{res.package_name}' ({res.old_version} -> {res.new_version}) "
            f"deviates significantly from baseline: {joined}. Recommended Action: {res.verdict} installation."
        )

    def _generate_markdown_report(self, res: DiffResult) -> str:
        status_emoji = "🚨" if res.verdict == "BLOCK" else ("⚠️" if res.verdict == "WARN" else "✅")
        
        lines = [
            f"### {status_emoji} Tripwire Supply Chain Analysis: `{res.package_name}`",
            f"**Version Transition:** `{res.old_version}` -> `{res.new_version}` | **Risk Score:** `{res.risk_score}/10.0` ({res.severity.value}) | **Verdict:** `{res.verdict}`",
            "",
            f"> {res.executive_summary}",
            "",
        ]

        if res.honeytoken_trips:
            lines.append("#### 🪤 Canary Honeytoken Breaches (Zero-Tolerance)")
            lines.append("| Token Type | Target Asset | Breached By | Evidence |")
            lines.append("|---|---|---|---|")
            for trip in res.honeytoken_trips:
                lines.append(f"| **{trip.token_type}** | `{trip.accessed_target}` | `{trip.process_binary}` (PID {trip.pid}) | {trip.evidence_snippet} |")
            lines.append("")

        if res.deltas:
            lines.append("#### 🔍 Behavioral Delta Anomalies (vs Baseline)")
            lines.append("| Category | Severity | Finding | Previous Release | New Release | MITRE |")
            lines.append("|---|---|---|---|---|---|")
            for d in res.deltas:
                mitre_str = f"[{d.mitre_attack_id}](https://attack.mitre.org/techniques/{d.mitre_attack_id.replace('.', '/')})" if d.mitre_attack_id else "-"
                lines.append(f"| **{d.category.upper()}** | `{d.severity.value}` | {d.summary} | `{d.old_state or '-'}` | `{d.new_state or '-'}` | {mitre_str} |")
            lines.append("")

        lines.append("#### 📊 Empirical Normalization Metrics")
        lines.append(f"- **Baseline Syscalls Recorded:** `{res.old_syscall_count:,}`")
        lines.append(f"- **Candidate Syscalls Recorded:** `{res.new_syscall_count:,}`")
        lines.append(f"- **Benign Operational Noise Filtered:** `{res.raw_delta_noise_filtered:,}` events (differential cancellation)")
        lines.append(f"- **True Anomalies Isolated:** `{res.meaningful_anomalies_count}`")

        return "\n".join(lines)
