# R3X-BugBounty Architecture Specification

`R3X-BugBounty` is designed around an autonomous multi-agent hierarchy enforcing strict scope containment and empirical evidence verification.

## 1. High-Level System Architecture

```mermaid
graph TD
    User([Security Auditor / Master]) -->|CLI / Interactive REPL| CLI[R3X CLI Engine]
    CLI --> ScopeGate{Scope Guardian Agent}
    
    subgraph "Authorization & Safety Core"
        ScopeGate -->|Domain Allowlist / Exclusions / Rate Limits| Approved[Authorized Flow]
        ScopeGate -->|Out-of-Scope Target| Reject[Block & Log Audit Event]
    end
    
    subgraph "Orchestration & Intelligence"
        Approved --> Hermes[Hermes Master Orchestrator]
        Hermes --> Brain[AI Pentest Brain]
        Hermes --> Mixer[R3X AI Mixer]
    end
    
    subgraph "Multi-Provider AI Mixer"
        Mixer --> NIM[NVIDIA NIM]
        Mixer --> OpenRouter[OpenRouter / Claude]
        Mixer --> OpenAI[OpenAI GPT-4o]
        Mixer --> Gemini[Google Gemini]
        Mixer --> Ollama[Local Ollama]
    end
    
    subgraph "Autonomous Security Agents"
        Hermes --> Recon[Recon Agent]
        Hermes --> WebSec[Web Security Agent]
        Hermes --> APISec[API Security Agent]
        Hermes --> JSSec[JavaScript Analysis Agent]
        Hermes --> CVEIntel[CVE Intelligence Agent]
    end
    
    subgraph "Verification & Evidence Engine"
        WebSec --> Verifier[False Positive Verification Agent]
        APISec --> Verifier
        Verifier -->|Dual-Model Consensus| Confirmed[Consensus Verified]
        Confirmed --> Collector[Evidence Collector Agent]
        Collector --> Redactor[Secret Sanitizer]
        Redactor --> Hasher[SHA-256 Digest Engine]
        Hasher --> SQLite[(SQLite Memory Database)]
    end
    
    subgraph "Reporting"
        SQLite --> Reporter[Report Generator Agent]
        Reporter --> OutReports[HTML / Markdown / JSON / PDF]
    end
```

## 2. Scope Guardian Gate

Every network action is intercepted by `ScopeGuardian`:
1. **Target Allowlist:** Matching against explicit domain and approved wildcard subdomains.
2. **Exclusion Traps:** Strict checks against `*.gov`, `*.mil`, sensitive endpoints (`logout`, `delete`, `shutdown`).
3. **Redirect Protection:** Inspects all `Location` HTTP headers; terminates requests if redirection attempts to escape the authorized scope.
4. **Emergency Stop:** Immediate halt mechanism callable globally.

## 3. Evidence-First Integrity

Findings are never admitted based purely on language model speculation. Every record requires:
- **Raw Request & Response trace**
- **Automatic Secrets Redaction** (JWTs, session IDs, passwords, API tokens)
- **Immutable SHA-256 Digest**
- **Dual-Model Cross Verification** for High and Critical vulnerabilities.
