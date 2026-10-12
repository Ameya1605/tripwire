"""Dynamic Information Flow & Secret Taint Tracking Engine for Tripwire."""

import math
import base64
from typing import Dict, List, Optional, Tuple, Set
from pydantic import BaseModel, Field


class TaintFlowHop(BaseModel):
    step: int
    stage: str  # SOURCE, TRANSFORMATION, EXFILTRATION_SINK
    entity: str
    evidence: str
    entropy: float = 0.0


class TaintIncident(BaseModel):
    """Correlated end-to-end data flow from sensitive source to network egress."""
    taint_id: str
    source_target: str
    sink_target: str
    hops: List[TaintFlowHop] = Field(default_factory=list)
    exfiltrated_entropy: float = 0.0
    is_encrypted_or_obfuscated: bool = False
    confidence: float = 1.0
    mitre_attack_id: str = "T1567.002"
    mitre_attack_technique: str = "Exfiltration to Cloud Storage / Webhook"


class TaintTracker:
    """
    Tracks dynamic information flow from sensitive sources (honeytokens, credentials)
    through memory/transforms to outbound network sinks, detecting encrypted or
    base64-encoded exfiltration via Shannon entropy anomaly detection.
    """

    @staticmethod
    def calculate_shannon_entropy(data: str) -> float:
        """
        Calculates Shannon entropy: H(X) = -sum(P(x) * log2(P(x))).
        Natural English/code is typically 2.5 - 3.8.
        Base64/Encrypted exfiltration payloads typically exceed 4.5 - 5.5.
        """
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        freq: Dict[str, int] = {}
        for char in data:
            freq[char] = freq.get(char, 0) + 1

        for count in freq.values():
            p = count / length
            entropy -= p * math.log2(p)
        return round(entropy, 2)

    def analyze_taint_flow(
        self,
        accessed_sources: List[str],
        network_payloads: List[str],
        canary_tokens: Set[str],
    ) -> List[TaintIncident]:
        """
        Correlates read operations on sensitive sources with outbound network payloads.
        Detects cleartext leakage, base64-encoded canaries, and high-entropy payloads.
        """
        incidents: List[TaintIncident] = []

        if not accessed_sources:
            return incidents

        # Precompute base64 encoded versions of canaries
        encoded_canaries = {}
        for token in canary_tokens:
            if len(token) >= 6:
                b64 = base64.b64encode(token.encode()).decode()
                encoded_canaries[token] = b64

        for payload in network_payloads:
            entropy = self.calculate_shannon_entropy(payload)
            is_high_entropy = entropy > 4.5 and len(payload) > 24

            for source in accessed_sources:
                # 1. Direct Cleartext Canary Match
                for token in canary_tokens:
                    if token in payload:
                        incidents.append(
                            TaintIncident(
                                taint_id=f"TAINT-DIRECT-{len(incidents)+1}",
                                source_target=source,
                                sink_target="Outbound Network Payload",
                                hops=[
                                    TaintFlowHop(step=1, stage="SOURCE", entity=source, evidence="Read sensitive asset"),
                                    TaintFlowHop(step=2, stage="EXFILTRATION_SINK", entity="HTTP/Socket", evidence=f"Direct canary match '{token}' in payload", entropy=entropy),
                                ],
                                exfiltrated_entropy=entropy,
                                is_encrypted_or_obfuscated=False,
                                confidence=1.0,
                            )
                        )
                        break

                # 2. Obfuscated / Base64 Encoded Canary Match
                for token, b64_variant in encoded_canaries.items():
                    if b64_variant in payload:
                        incidents.append(
                            TaintIncident(
                                taint_id=f"TAINT-B64-{len(incidents)+1}",
                                source_target=source,
                                sink_target="Outbound Network Payload",
                                hops=[
                                    TaintFlowHop(step=1, stage="SOURCE", entity=source, evidence="Read sensitive asset"),
                                    TaintFlowHop(step=2, stage="TRANSFORMATION", entity="Base64 / Packing", evidence="Data encoded via base64 buffer transform"),
                                    TaintFlowHop(step=3, stage="EXFILTRATION_SINK", entity="HTTP/Socket", evidence=f"Base64-encoded canary signature '{b64_variant[:12]}...' detected", entropy=entropy),
                                ],
                                exfiltrated_entropy=entropy,
                                is_encrypted_or_obfuscated=True,
                                confidence=0.98,
                            )
                        )
                        break

                # 3. High-Entropy Secret Exfiltration Anomaly (Correlated Read -> High Entropy Egress)
                if is_high_entropy and not incidents:
                    incidents.append(
                        TaintIncident(
                            taint_id=f"TAINT-ANOMALY-{len(incidents)+1}",
                            source_target=source,
                            sink_target="Outbound Network Payload",
                            hops=[
                                TaintFlowHop(step=1, stage="SOURCE", entity=source, evidence="Read sensitive asset"),
                                TaintFlowHop(step=2, stage="TRANSFORMATION", entity="Entropy Spike", evidence=f"High Shannon entropy payload: H={entropy} (Threshold > 4.5)", entropy=entropy),
                                TaintFlowHop(step=3, stage="EXFILTRATION_SINK", entity="HTTP/Socket", evidence=f"Outbound egress buffer length {len(payload)} bytes", entropy=entropy),
                            ],
                            exfiltrated_entropy=entropy,
                            is_encrypted_or_obfuscated=True,
                            confidence=0.85,
                        )
                    )

        return incidents
