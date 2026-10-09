# PhishGuard Architecture Specification

PhishGuard is an offline-first, deterministic, explainable phishing detection platform. It is engineered with **zero external runtime dependencies**, operating entirely via native ES Modules in modern web browsers and Node.js 20+.

```
               ┌────────────────────────────────────────────────────────┐
               │                  User Input (URL / Text)               │
               └───────────────────────────┬────────────────────────────┘
                                           │
                                           ▼
               ┌────────────────────────────────────────────────────────┐
               │              Input Routing & Normalization             │
               │      - Trims whitespace & unwraps delimiters           │
               │      - Injects protocol if absent                      │
               │      - Strips trailing FQDN dot & downcases host       │
               └───────────────────────────┬────────────────────────────┘
                                           │
                                           ▼
               ┌────────────────────────────────────────────────────────┐
               │          RFC 3986 Standard Parser & Suffix Matcher     │
               │      - Extracts scheme, userinfo, port, path, query    │
               │      - Matches longest public suffix (suffixes.json)   │
               │      - Isolates Subdomain vs Registrable Domain        │
               │      - Detects Raw IP hosts (dotted, hex, octal, dec)  │
               └───────────────────────────┬────────────────────────────┘
                                           │
                                           ▼
               ┌────────────────────────────────────────────────────────┐
               │                  Rule Registry Pipeline                │
               │   Runs 11 isolated, side-effect-free heuristic rules   │
               │   Each rule emits: { triggered, evidence, segment }    │
               └───────────────────────────┬────────────────────────────┘
                                           │
                                           ▼
               ┌────────────────────────────────────────────────────────┐
               │             Scoring & Explainability Engine            │
               │   - Checks Exact Allow-List (allowlist.json)           │
               │   - Suppresses cosmetic false positives (Dampening)    │
               │   - Applies Compound Risk Bonuses (e.g. Brand + TLD)   │
               │   - Maps score (0-100) to Safe / Suspicious / Phishing │
               │   - Highlights primary anomalous URL segment           │
               └───────────────────────────┬────────────────────────────┘
                                           │
                                           ▼
               ┌────────────────────────────────────────────────────────┐
               │              Forensic Security Output Object           │
               │  { score, verdict, segments, evidence[], advice[] }    │
               └────────────────────────────────────────────────────────┘
```

## System Architecture Diagram

```mermaid
graph TD
    A[Raw Input: URL or Message Text] --> B[analyze Entry Point]
    B -->|URL string| C[parser.js: parseUrl]
    B -->|Message Body| D[Text Extractor: URLs + Urgency Lexicon]
    
    C --> E[URL Normalization & eTLD+1 Decomposition]
    E --> F[Rule Registry: ALL_RULES]
    
    subgraph Rule Evaluation Layer
        F --> R1[ip-host]
        F --> R2[userinfo]
        F --> R3[brand-impersonation]
        F --> R4[typosquatting]
        F --> R5[homograph-idn]
        F --> R6[subdomain-depth]
        F --> R7[suspicious-tld]
        F --> R8[url-shortener]
        F --> R9[credential-keywords]
        F --> R10[insecure-scheme]
        F --> R11[url-structure]
    end

    R1 & R2 & R3 & R4 & R5 & R6 & R7 & R8 & R9 & R10 & R11 --> G[scoring.js: scoreParsedUrl]

    subgraph Scoring & Attribution Layer
        G --> H[Allow-List Verification]
        H -->|Verified Authentic Domain| I[Cosmetic Dampening]
        G --> J[Compound Combination Amplification]
        I & J --> K[Score Clamping: 0 - 100]
        K --> L[Verdict Mapping: Safe / Suspicious / Phishing]
    end

    L --> M[Forensic Output Model]
    M --> N[UI Render: Segment Breakdown, SVG Gauge, Evidence Cards]
```

## Module Directory Structure

```mermaid
graph LR
    subgraph src/
        direction TB
        E[engine/] --> P[parser.js]
        E --> S[scoring.js]
        E --> C[config.js]
        E --> R[rules/]
        
        D[data/] --> D1[brands.json]
        D --> D2[suffixes.json]
        D --> D3[allowlist.json]
        D --> D4[tlds.json]
        D --> D5[shorteners.json]
        D --> D6[lexicon.json]
        
        U[ui/] --> M1[main.js]
        U --> M2[render.js]
        U --> M3[dom.js]
        
        ST[styles/] --> T1[tokens.css]
        ST --> T2[base.css]
        ST --> T3[layout.css]
        ST --> T4[components.css]
    end
```

## Core Design Tenets

1. **Deterministic Execution**:
   Unlike stochastic LLM or opaque machine learning models that can hallucinate or fluctuate across runs, PhishGuard generates deterministic scores and explicit forensic citations.
2. **Offline Resilience**:
   The engine does not initiate outbound HTTP requests, perform DNS lookups, or contact third-party threat intelligence APIs. It cannot leak user browsing activity, cannot suffer network timeouts, and operates in air-gapped environments.
3. **Defense Against Evasion**:
   By extracting the registrable domain (eTLD+1) prior to inspection, PhishGuard remains immune to subdomain impersonation attacks such as `paypal.com.secure-update.xyz`.
