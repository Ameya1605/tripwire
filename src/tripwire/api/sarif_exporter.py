"""SARIF 2.1.0 Export Engine for GitHub Advanced Security Code Scanning."""

from typing import Dict, Any, List
from tripwire.models.report import DiffResult, RiskSeverity


def export_diff_to_sarif(diff_result: DiffResult) -> Dict[str, Any]:
    """
    Transforms a DiffResult into official OASIS SARIF 2.1.0 JSON representation
    for automated ingestion by GitHub Code Scanning and security dashboards.
    """
    rules: List[Dict[str, Any]] = []
    results: List[Dict[str, Any]] = []
    seen_rules = set()

    for delta in diff_result.deltas:
        rule_id = delta.mitre_attack_id or f"TW-{delta.category.upper()}-001"
        if rule_id not in seen_rules:
            seen_rules.add(rule_id)
            rules.append({
                "id": rule_id,
                "name": delta.mitre_attack_technique or f"Tripwire_{delta.category}_Anomaly",
                "shortDescription": {
                    "text": delta.summary,
                },
                "fullDescription": {
                    "text": delta.detail,
                },
                "defaultConfiguration": {
                    "level": "error" if delta.severity in [RiskSeverity.CRITICAL, RiskSeverity.HIGH] else "warning"
                },
            })

        # Map severity to SARIF level
        sarif_level = "error" if delta.severity in [RiskSeverity.CRITICAL, RiskSeverity.HIGH] else ("warning" if delta.severity == RiskSeverity.MEDIUM else "note")

        results.append({
            "ruleId": rule_id,
            "level": sarif_level,
            "message": {
                "text": f"[{delta.severity.value}] {delta.summary}: {delta.detail}",
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": "package.json",
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": 1,
                            "startColumn": 1,
                        },
                    }
                }
            ],
            "properties": {
                "packageName": diff_result.package_name,
                "oldVersion": diff_result.old_version,
                "newVersion": diff_result.new_version,
                "riskScore": diff_result.risk_score,
                "observedBehavior": delta.new_state,
                "baselineBehavior": delta.old_state,
            }
        })

    sarif_doc = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Tripwire-DDBA",
                        "semanticVersion": "0.1.0",
                        "informationUri": "https://github.com/tripwire-sec/tripwire",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ]
    }

    return sarif_doc
