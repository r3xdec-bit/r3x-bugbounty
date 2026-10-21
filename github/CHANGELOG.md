# Changelog

All notable changes to **R3X-BugBounty** will be documented in this file.

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
