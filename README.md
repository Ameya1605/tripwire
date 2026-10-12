# ⚡ Tripwire: Differential Dynamic Behavioral Analysis (DDBA) for Software Supply Chains

[![Python](https://img.shields.io/badge/Python-3.11%20%7C%203.12%20%7C%203.13-blue.svg)](https://python.org)
[![Docker](https://img.shields.io/badge/Sandbox-Docker%20%2B%20Linux%20strace-2496ED.svg)](https://docker.com)
[![SARIF](https://img.shields.io/badge/Standard-SARIF%202.1.0-8A2BE2.svg)](https://docs.github.com/en/code-security/code-scanning)
[![Evaluation Benchmark](https://img.shields.io/badge/Benchmark-100%25%20Recall%20%7C%200%25%20FPR-success.svg)](#-empirical-evaluation-benchmark)
[![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)](LICENSE)

> **"Don't read the code. Watch it execute. Diff the behavior against the previous release."**

Tripwire is an active behavioral supply chain defense engine. When an open-source dependency updates, Tripwire detonates both the predecessor release ($v_{n-1}$) and candidate release ($v_n$) in isolated ephemeral Linux sandboxes, records kernel-level POSIX syscall telemetry (`strace`), filters non-deterministic operational noise, and isolates **behavioral delta anomalies**.

---

## 🔬 The Core Thesis: Why Single-Run Dynamic Analysis Fails

Modern supply chain attacks (*EventStream*, *UA-Parser-JS*, *Node-IPC*, *Colors sabotage*, *XZ-Utils*) routinely bypass static analysis (SAST) through base64 packing, dynamic string evaluation (`eval()`), or obfuscation.

Dynamic analysis platforms (like OpenSSF Package Analysis or GuardDog) detonate packages in a sandbox to watch runtime activity. However, single-point dynamic analysis suffers from a severe **false positive crisis** (academically shown to flag up to 4,600+ benign packages). Legitimate packages frequently execute install scripts (`postinstall`), compile C++ extensions via `node-gyp`, query CPU architectures, download prebuilt platform binaries (e.g. `esbuild`, `puppeteer`, `sharp`), and make analytics calls.

### The Tripwire Differential Solution
Tripwire introduces **Differential Dynamic Behavioral Analysis (DDBA)**:

$$\Delta \mathcal{B} = \mathcal{B}(v_n) \ominus \mathcal{B}(v_{n-1})$$

- If version 2.1.0 always compiled a native binary during install, version 2.1.1 doing the same generates **zero alert noise**.
- If version 2.1.1 suddenly opens an outbound socket to an unmapped host, executes `/bin/sh`, reads `~/.ssh/id_rsa`, or accesses an injected honeytoken canary, the **behavioral delta triggers an immediate, high-fidelity block**.

---

## 🏆 Empirical Evaluation Benchmark

Tested across a ground-truth dataset of simulated real-world supply chain incidents (EventStream, UA-Parser-JS, Node-IPC wiper, Canary exfiltration) and 20 benign npm version bumps:

| Evaluation Metric | Single-Snapshot Dynamic (OpenSSF Baseline) | Tripwire DDBA (Differential Delta) | Scientific Improvement |
|---|---|---|---|
| **Detection Recall** *(Attacks Caught)* | **100.0%** (5/5) | **100.0%** (5/5) | **Identical (100% recall)** |
| **False Positive Rate** *(Benign Flagged)* | **40.0%** (8/20) | **0.0%** (0/20) | **-40.0% noise reduction** |
| **Precision** *(True Malicious Ratio)* | **38.5%** | **100.0%** | **+61.5% higher fidelity** |
| **Overall F1 Score** | **55.6** | **100.0** | **+44.4 improvement** |

*Reproduce locally:* `tripwire benchmark`

---

## 🏛️ System Architecture

```text
       PR / CLI / API Ingestion (tripwire diff express@4.18.1 express@4.18.2)
                                       │
            ┌──────────────────────────┴──────────────────────────┐
            ▼                                                     ▼
┌────────────────────────┐                             ┌────────────────────────┐
│  Sandbox A: Baseline   │                             │  Sandbox B: Candidate  │
│  (Docker + Non-Root)   │                             │  (Docker + Non-Root)   │
│  Honeytokens Injected  │                             │  Honeytokens Injected  │
│  Syscall Tracer        │                             │  Syscall Tracer        │
└───────────┬────────────┘                             └───────────┬────────────┘
            │                                                     │
            └──────────────────────────┬──────────────────────────┘
                                       ▼
                       Algorithmic Normalization Engine
                       • Path Abstraction (TMP_NPM, APP_DIR)
                       • PID Hierarchy Canonicalizer
                       • Repetition Loop Folding
                                       │
                                       ▼
                       Differential Delta Engine (ΔB)
                                       │
                                       ▼
                       Threat Scorer & MITRE ATT&CK
                                       │
         ┌───────────────────┬─────────┴─────────┬───────────────────┐
         ▼                   ▼                   ▼                   ▼
    Terminal CLI       GitHub Action        SARIF 2.1.0        Web Dashboard
    (Rich Panels)      (PR Comments)      (Code Scanning)     (React 19 / Vite)
```

---

## 🪤 Multi-Tier Honeytoken Deception Subsystem

Tripwire plants synthetic canary secrets directly inside the sandbox before detonation:
1. **Decoy AWS Credentials:** `~/.aws/credentials` (`AKIA_TRIPWIRE_CANARY_UUID`)
2. **Decoy SSH Keys:** `~/.ssh/id_rsa` (Canary-tagged 2048-bit key)
3. **Decoy NPM Token:** `~/.npmrc` (`_authToken=npm_canary_tripwire_token`)
4. **Decoy Environment Variables:** `AWS_SECRET_ACCESS_KEY`, `NPM_TOKEN`, `SLACK_WEBHOOK_URL`

Any access to these tokens flags an immediate **CRITICAL SEVERITY (Score: 10.0)** breach with MITRE ATT&CK technique **T1552.001 (Credentials in Files)**.

---

## 🚀 Quickstart & Installation

### 1. Installation
```bash
git clone https://github.com/tripwire-sec/tripwire.git
cd tripwire
python -m venv venv
source venv/bin/activate  # On Windows: .\venv\Scripts\activate
pip install -e .
```

### 2. Compare Package Versions
```bash
# Compare a benign minor upgrade (Passes with 0 risk)
tripwire diff express@4.18.1 express@4.18.2

# Export to SARIF 2.1.0 for GitHub Code Scanning
tripwire diff express@4.18.1 express@4.18.2 --format sarif --out tripwire.sarif

# Run full evaluation benchmark
tripwire benchmark
```

### 3. Launch REST API & Web Forensic Dashboard
```bash
# Launch API server
tripwire serve --port 8000

# In dashboard directory:
cd dashboard
npm install
npm run dev
```

---

## 🛡️ Prior Art & Academic Context
Tripwire builds upon and directly addresses the limitations of pioneering supply-chain tools:
- **OpenSSF Package Analysis:** Pioneered dynamic package detonation via Docker and strace. Tripwire contributes the release-over-release differential normalization model that solves the false-positive problem.
- **Socket.dev / Phylum:** Excellent manifest and static AST heuristic analysis. Tripwire addresses obfuscated, polymorphic, and encrypted runtime payloads that bypass static AST parsing.
- **GuardDog (Datadog):** Semgrep-based static rules for malicious packages.

---

## ⚖️ Known Limitations & Threat Evasion
- **Sleep & Delay Evasion:** Attackers may set long timers (`setTimeout(..., 72h)`) to evade execution sandboxes. Tripwire mitigates this by instrumenting timer-setting syscalls and postinstall entry points.
- **Anti-Sandboxing Fingerprinting:** Malware attempting to detect Docker or virtualization namespaces. Disclosed in Tripwire's evaluation suite as an ongoing research vector.

---

## 📄 License
Licensed under the Apache License, Version 2.0.
