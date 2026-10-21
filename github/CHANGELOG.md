# Changelog

All notable changes to **R3X-BugBounty** will be documented in this file.

## [2.0.0] - 2026-10-21 (V2 Evolution Upgrade)

### Added
- **R3X Neural Brain** (`r3x/core/neural_brain.py`): Central cognitive correlation engine that automatically synthesizes discrete discoveries into complex multi-stage attack chains.
- **Multi-Agent Adversarial Debate Engine** (`r3x/mixer/debate.py`): 3-agent deliberation protocol (Prosecutor vs Defender adjudicated by Chief Judge) eliminating false positives.
- **Intelligent Attack Surface Graph** (`r3x/core/graph.py`): NetworkX-powered target topology and Rich hierarchical terminal tree visualizer.
- **Knowledge Memory & Pattern Intelligence** (`r3x/memory/knowledge.py`): Cross-audit vulnerability heuristics and token-optimized context compressor with zero data leakage.
- **Self-Healing Automation Framework** (`r3x/core/self_healing.py`): Automated failure diagnostics (missing binaries, 429 rate limits, timeouts) with safe typed retry logic.
- **Smart Scan Optimizer** (`r3x/core/optimizer.py`): Pre-scan protocol analysis and target fingerprinting that dynamically eliminates redundant scanner calls.
- **AI Evidence Validator Agent** (`r3x/evidence/validator.py`): Cryptographic SHA-256 integrity checker and zero-leakage credential redaction auditor.
- **Real-Time Operational Dashboard** (`r3x/cli/dashboard.py`): Live terminal status dashboard tracking agents, tasks, costs, tokens, and confirmed findings.
- **Plugin Marketplace & Extension Framework** (`r3x/plugins/manager.py`): Hot-pluggable tool architecture with strict capability privilege enforcement.
- **Bug Bounty Intelligence Reporter** (`r3x/reports/intelligence.py`): One-click HackerOne, Bugcrowd, and Intigriti platform-ready Markdown submission generator.
- **AI Mixer V2 Evolution**:
  - `BudgetGuard` (`r3x/mixer/budget_guard.py`): Strict financial spending cap enforcement with hard budget locks.
  - `ModelScoringEngine` (`r3x/mixer/scoring.py`): Dynamic multi-metric evaluation of latency, cost, stability, and task affinity.
  - Smart fallback retaining conversational context across provider failures.
- **End-to-End Pipeline Verification**: Full integration test suite against a local mock vulnerable target (`tests/mock_target_server.py`) with pause/resume support.

### Changed & Hardened
- **Database Resource Management**: Upgraded SQLite database layer with context-managed connection closures to eliminate file descriptor leaks.
- **Prompt Injection Defense**: Sanitization and XML-tag encapsulation for untrusted target HTTP headers and response bodies.
- **Static Security Auditing**: Full Bandit, Ruff, and Pip-Audit compliance (0 High, 0 Medium, 0 Low vulnerabilities across entire codebase).

## [1.0.0] - 2026-10-21

### Added
- **Core CLI & REPL**: Interactive prompt with auto-completion, Rich banners, and dynamic status matrix.
- **R3X AI Mixer**: Multi-key, multi-provider model routing supporting NVIDIA NIM, OpenRouter, OpenAI, Gemini, and local Ollama.
- **Encrypted Local Keystore**: PBKDF2/Fernet encryption for API keys with load-balancing and backoff retry.
- **Dual-Model Consensus Verifier**: Cross-model verification to eliminate false positives on critical findings.
- **Hermes Master Orchestrator**: Adaptive planning, task delegation, and context management compatible with NousResearch/hermes-agent.
- **HexStrike AI MCP Adapter**: Protocol-level dynamic discovery of MCP security tools and typed schema validation (v6.0).
- **Scope Guardian Gate**: Strict domain allowlists, URL exclusions, redirect traps prevention, and rate-limiting.
- **11 Autonomous Agents**: Specialized agents for Recon, Web, API, JavaScript, CVE Intel, False Positive verification, Evidence Collection, and Reporting.
- **Evidence-First Engine**: Automatic secrets redaction (Bearer tokens, session cookies, passwords) and SHA-256 evidence hashing.
- **Multi-Format Report Generator**: Export professional submission-ready reports in HTML, Markdown, JSON, and PDF formats.
- **Automated Installer (`install.sh`)**: Multi-distro installer for Kali Linux, Arch Linux, Debian, and Ubuntu.
