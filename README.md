<div align="center">

<img src="../assets/logo.png" alt="R3X-BugBounty Logo" width="260"/>

# R3X-BugBounty — Autonomous AI Security Framework
### Multi-Agent Autonomous Security Auditing & Bug Bounty Assessment Platform

[![Python](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Security-Audit%20%26%20Recon-red.svg)](https://github.com/r3xdec/r3x-bugbounty)
[![Multi-Agent](https://img.shields.io/badge/Agents-11%20Autonomous-purple.svg)](https://github.com/r3xdec/r3x-bugbounty)
[![Evidence-First](https://img.shields.io/badge/Evidence-SHA--256%20Verified-cyan.svg)](https://github.com/r3xdec/r3x-bugbounty)

[English](README.md) • [العربية](README_AR.md) • [Architecture](ARCHITECTURE.md) • [Installation](INSTALLATION.md) • [Changelog](CHANGELOG.md)

</div>

---

## 🎯 Overview

**R3X-BugBounty** is an open-source, terminal-native cybersecurity assessment framework driven by 11 autonomous AI agents. Built strictly for authorized security assessments, penetration testing, and Bug Bounty research, R3X coordinates standard security tools, enforces domain boundary containment via the **Scope Guardian**, and executes dual-model consensus verification to eradicate false positives.

---

## ⚡ Key Highlights

- **Interactive Cyber REPL**: Terminal shell with tab auto-completion, live diagnostic matrix, and Rich styling.
- **R3X AI Mixer**: Add multiple independent API keys per provider across **NVIDIA NIM**, **OpenRouter**, **OpenAI**, **Gemini**, and **Ollama Local**. Features automatic fallback chains and token cost tracking.
- **Dual-Model Consensus Verifier**: Compares independent reasoning from two separate AI models before validating any critical security finding.
- **Hermes Agent Integration**: Decoupled adapter compatible with [NousResearch/hermes-agent](https://github.com/NousResearch/hermes-agent) for dynamic pentest planning and persistent memory.
- **HexStrike AI MCP Adapter**: Protocol-level dynamic discovery of MCP security tools compatible with [HexStrike AI MCP v6.0](https://github.com/0x4m4/hexstrike-ai).
- **Scope Guardian Gate**: Absolute enforcement of domain allowlists, URL exclusions, redirect trap defense, and rate-limiting.
- **Evidence-First Engine**: Automatic redaction of sensitive credentials (JWTs, session IDs, passwords) with immutable SHA-256 evidence hashing.
- **Professional Reporting**: Generates submission-ready Bug Bounty reports in **HTML**, **Markdown**, **JSON**, and **PDF** formats.

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
| 8 | **FalsePositiveVerificationAgent** | Coordinates cross-model consensus verification to eliminate false positives |
| 9 | **EvidenceCollectorAgent** | Sanitizes HTTP traces, computes SHA-256 hashes, and persists memory |
| 10 | **AIMixerAgent** | Manages LLM router quotas, load balancing, cost tracking, and backoff retries |
| 11 | **ReportGeneratorAgent** | Compiles verified findings into submission-grade executive reports |

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
# System Diagnostics
r3x doctor

# Project & Target Setup
r3x project new my-target
r3x target add https://target.example.com --project my-target
r3x scope import scope.json --project my-target

# Multi-Provider AI Mixer Management
r3x mixer add nvidia
r3x mixer add openrouter
r3x mixer add ollama
r3x mixer list
r3x mixer status

# Security Assessments
r3x scan --quick --project my-target
r3x scan --full --project my-target
r3x scan --api --project my-target

# AI Brain Investigation
r3x ai --target https://target.example.com

# Findings, Evidence & History
r3x findings --project my-target
r3x evidence
r3x history
r3x resume
r3x diff scan_id_1 scan_id_2

# Reporting
r3x report --html --project my-target
r3x report --md --project my-target
r3x report --json --project my-target
```

---

## 🔒 Security & Scope Guardian Rules

R3X enforces defensive rules of engagement:
1. **Zero Destructive Testing**: Brute-force attacks, sensitive database extraction, and weaponized exploit payloads are strictly prohibited.
2. **Strict Domain Allowlist**: All scanner probes verify targets against the allowlist before transmitting packets.
3. **Emergency Stop**: Run `r3x` and trigger immediate halt at any point during active operations.

---

## 📄 License

Distributed under the **MIT License**. See [LICENSE](LICENSE) for details.
