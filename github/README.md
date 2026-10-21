<div align="center">

```
 ██████╗ ██████╗ ██╗  ██╗██████╗ ███████╗ ██████╗
 ██╔══██╗╚════██╗╚██╗██╔╝██╔══██╗██╔════╝██╔════╝
 ██████╔╝ █████╔╝ ╚███╔╝ ██║  ██║█████╗  ██║     
 ██╔══██╗ ╚═══██╗ ██╔██╗ ██║  ██║██╔══╝  ██║     
 ██║  ██║██████╔╝██╔╝ ██╗██████╔╝███████╗╚██████╗
 ╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝╚═════╝ ╚══════╝ ╚═════╝
```

# R3X-BugBounty — Autonomous AI Security Framework [v2.0.0]
### Multi-Agent Autonomous Security Auditing & Bug Bounty Assessment Platform

[![Python](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/)
[![Version](https://img.shields.io/badge/Release-v2.0.0--Evolution-green.svg)](https://github.com/r3xdec/r3x-bugbounty)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Security-Bandit%20Passing-brightgreen.svg)](https://github.com/r3xdec/r3x-bugbounty)
[![Multi-Agent](https://img.shields.io/badge/Agents-11%20Autonomous%20%2B%20Debate-purple.svg)](https://github.com/r3xdec/r3x-bugbounty)
[![Evidence-First](https://img.shields.io/badge/Evidence-SHA--256%20Verified-cyan.svg)](https://github.com/r3xdec/r3x-bugbounty)

[English](README.md) • [العربية](github/README_AR.md) • [Architecture](github/ARCHITECTURE.md) • [Installation](github/INSTALLATION.md) • [Changelog](github/CHANGELOG.md)

</div>

---

## 🎯 Overview

**R3X-BugBounty** is an open-source, terminal-native cybersecurity assessment framework driven by 11 autonomous AI agents and cognitive correlation engines. Built strictly for authorized security assessments, penetration testing, and Bug Bounty research, R3X coordinates standard security tools, enforces domain boundary containment via the **Scope Guardian**, conducts **3-Agent Adversarial Debates** to eradicate false positives, and builds real-time attack surface topology graphs.

---

## ⚡ Key Highlights (v2.0.0 Evolution)

- **Interactive Cyber REPL & Live Dashboard**: Terminal shell with tab auto-completion, live diagnostic matrix (`r3x dashboard`), and authentic service telemetry.
- **R3X Neural Brain**: Central cognitive correlation engine that automatically chains isolated findings into high-impact multi-stage attack scenarios.
- **Multi-Agent Adversarial Debate Engine**: 3-Agent dialectic court (Prosecutor vs. Defender adjudicated by Chief Judge) evaluating empirical evidence traces.
- **Intelligent Attack Surface Graph**: NetworkX-powered target topology with interactive hierarchical terminal trees (`r3x surface`).
- **AI Mixer V2**: Multi-key, multi-provider model routing with **Budget Guard** (strict financial caps) and **Model Scoring Engine** (dynamic latency, cost, and task affinity optimization).
- **Self-Healing Automation Framework**: Safe failure diagnostics (rate-limits, timeouts, missing tools) with automated exponential backoff and typed retry.
- **Smart Scan Optimizer**: Pre-flight target analysis dynamically omitting redundant probes.
- **AI Evidence Validator**: Cryptographic SHA-256 verification and zero-leakage secret redaction audit.
- **Plugin Marketplace & Extension Framework**: Sandboxed tool extensions (`r3x plugin list`, `install`, `enable`, `disable`) with strict privilege containment.
- **Bug Bounty Intelligence Reporter**: One-click platform-ready Markdown submissions for HackerOne, Bugcrowd, and Intigriti (`r3x report --bounty`).
- **Hermes Master & HexStrike AI MCP v6.0**: Decoupled integration with NousResearch/hermes-agent and standard MCP tool discovery.

---

## 🤖 The 11 Autonomous Agents

| # | Agent Name | Core Responsibility |
|---|---|---|
| 1 | **HermesMasterOrchestrator** | Master task delegation, adaptive plan synthesis, and context preservation |
| 2 | **ScopeGuardianAgent** | Enforces domain allowlists, exclusions, redirect protection, and emergency stop |
| 3 | **ReconAgent** | Executes passive DNS intelligence, subdomain discovery, and tech fingerprinting |
| 4 | **WebSecurityAgent** | Audits HTTP security headers, CORS policies, Cookie flags, and TLS parameters |
| 5 | **APISecurityAgent** | Discovers and audits REST & GraphQL schemas (OpenAPI/Swagger) |
| 6 | **JSAnalysisAgent** | Statically analyzes client-side JavaScript for routes, endpoints, and leaked tokens |
| 7 | **CVEIntelligenceAgent** | Correlates component version disclosures with known vulnerability trends |
| 8 | **FalsePositiveVerificationAgent** | Coordinates 3-Agent adversarial debates to eliminate false positives |
| 9 | **EvidenceCollectorAgent** | Sanitizes HTTP traces, computes SHA-256 hashes, and persists memory |
| 10 | **AIMixerAgent** | Manages LLM router quotas, dynamic scoring, financial budget guard, and backoff |
| 11 | **ReportGeneratorAgent** | Compiles verified findings into executive HTML, PDF, and platform-ready bounty submissions |

---

## 🚀 Quick Start

### 1. Automated Installation
Run the interactive installer supporting **Kali Linux**, **Arch Linux**, **Ubuntu**, and **Debian**:

```bash
git clone https://github.com/r3xdec/r3x-bugbounty.git
cd r3x-bugbounty
chmod +x install.sh
./install.sh
```

### 2. Launch the Interactive Shell
```bash
source .venv/bin/activate
r3x
```

---

## 🛠️ Essential Commands

```bash
# Real-Time Operational Telemetry & Diagnostics
r3x dashboard
r3x doctor

# Project & Target Setup
r3x project new my-target
r3x target add https://target.example.com --project my-target
r3x scope import scope.json --project my-target

# Multi-Provider AI Mixer Management & Budget Guard
r3x mixer add nvidia
r3x mixer add openrouter
r3x mixer add ollama
r3x mixer list
r3x mixer status

# Security Assessments
r3x scan --quick --project my-target
r3x scan --full --project my-target
r3x scan --api --project my-target

# Attack Surface Topology Graph
r3x surface --project my-target

# Plugin Marketplace
r3x plugin list
r3x plugin enable waf_fingerprint

# Findings, Evidence & History
r3x findings --project my-target
r3x evidence
r3x history
r3x resume

# Platform-Ready Bug Bounty Submissions & Reports
r3x report --bounty --project my-target
r3x report --html --project my-target
r3x report --md --project my-target
r3x report --json --project my-target
```

---

## 🔒 Security & Scope Guardian Rules

R3X enforces defensive rules of engagement:
1. **Zero Destructive Testing**: Brute-force attacks, sensitive database extraction, and weaponized exploit payloads are strictly prohibited.
2. **Strict Domain Allowlist**: All scanner probes verify targets against the allowlist before transmitting packets.
3. **Prompt Injection Defense**: Target HTTP responses and headers are sanitized and encapsulated in XML tags prior to LLM reasoning.
4. **Emergency Stop**: Run `r3x` and trigger immediate halt at any point during active operations.

---

## 📄 License

Distributed under the **MIT License**. See [LICENSE](LICENSE) for details.
