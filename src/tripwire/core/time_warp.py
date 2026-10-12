"""Time-Dilation and Anti-Sandbox Evasion Neutralization Engine for Tripwire."""

import re
from typing import List, Optional
from pydantic import BaseModel, Field


class EvasionAttempt(BaseModel):
    """Event recording an intercepted anti-sandbox or delayed-execution attempt."""
    technique: str  # SLEEP_BOMB, ENVIRONMENT_PROBE, CPU_COUNT_CHECK
    detail: str
    delay_requested_sec: float
    bypassed: bool = True
    mitre_attack_id: str = "T1497.003"
    mitre_attack_technique: str = "Virtualization/Sandbox Evasion: Time Based Evasion"


class TimeDilationEngine:
    """
    Detects and neutralizes time-bomb delays, sleep evasion, and anti-analysis
    probes used by sophisticated supply-chain malware to evade ephemeral sandboxes.
    """

    RE_SLEEP_SYSCALL = re.compile(
        r"nanosleep\(\{(?:tv_sec=)?(?P<sec>\d+)[^}]*\}\s*,\s*NULL\)"
    )
    RE_ALARM_SYSCALL = re.compile(r"alarm\((?P<sec>\d+)\)")

    def __init__(self):
        self.accumulated_virtual_offset_sec: float = 0.0
        self.evasion_attempts: List[EvasionAttempt] = []

    def inspect_trace_for_evasion(self, raw_trace_lines: List[str]) -> List[EvasionAttempt]:
        """
        Scans execution telemetry for sleep evasion syscalls and flags delayed triggers.
        """
        attempts = []
        for line in raw_trace_lines:
            match = self.RE_SLEEP_SYSCALL.search(line)
            if match:
                sec = int(match.group("sec"))
                if sec >= 5:  # Any install script sleeping > 5 seconds is highly anomalous
                    attempt = EvasionAttempt(
                        technique="SLEEP_BOMB",
                        detail=f"Detected execution delay of {sec} seconds via nanosleep(). Neutralized via virtual time acceleration.",
                        delay_requested_sec=float(sec),
                        bypassed=True,
                    )
                    attempts.append(attempt)
                    self.accumulated_virtual_offset_sec += sec

            alarm_match = self.RE_ALARM_SYSCALL.search(line)
            if alarm_match:
                sec = int(alarm_match.group("sec"))
                if sec > 10:
                    attempt = EvasionAttempt(
                        technique="TIMER_EVASION",
                        detail=f"Detected POSIX alarm signal timer for {sec}s.",
                        delay_requested_sec=float(sec),
                        bypassed=True,
                    )
                    attempts.append(attempt)

        self.evasion_attempts.extend(attempts)
        return attempts
