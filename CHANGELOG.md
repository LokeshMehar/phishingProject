# Changelog

All notable changes to the PhishGuard project are documented in this file.

## [2.0.0] - 2026-10-10

### Major Architectural Rebuild
- **Complete Rebuild**: Replaced naive substring and pseudo-regex checks from initial prototype with a fully modular, deterministic detection engine in ES Modules.
- **Robust URL Parsing**: Implemented standard `URL` parser normalization with automatic scheme inference, port isolation, userinfo extraction, and trailing dot normalization.
- **Registrable Domain (eTLD+1) Extraction**: Added bundled public suffix list supporting multi-part ccTLDs (`.co.uk`, `.co.in`, `.gov.in`, `.com.au`, `.com.br`) to prevent subdomain impersonation bypasses.
- **11 Modular Detection Rules**:
  - `ip-host`: Dotted, hex, octal, decimal, and IPv6 address hosts.
  - `userinfo`: Deceptive `@` tricks in URL authority.
  - `brand-impersonation`: 70+ brand trademark matches across subdomains, compound domains, and paths.
  - `typosquatting`: Damerau-Levenshtein edit distance 1-2 with length guards.
  - `homograph-idn`: Punycode `xn--` detection, Cyrillic lookalikes, and visual confusables.
  - `subdomain-depth`: Deep subdomain trees (>3 levels) and excessive hyphens.
  - `suspicious-tld`: Known high-abuse TLDs weighted as contextual signals.
  - `url-shortener`: Public redirect and shortening services.
  - `credential-keywords`: Sensitive authentication keywords in host and paths.
  - `insecure-scheme`: Plaintext HTTP and dangerous `javascript:` and `data:` schemes.
  - `url-structure`: Non-standard ports, excessive length, double-slash redirects, and percent-encoding abuse.
- **Explainable Scoring Engine**: Weighted scoring (0-100), allow-list dampening for authentic domains, combination bonuses, and primary threat segment attribution.
- **Benchmark Test Suite**: 138-sample curated corpus (69 legitimate, 69 phishing) evaluated using Node's native `node --test` runner with 100% precision and recall.
- **Modern Security Operations UI**:
  - Signature segmented URL decomposition pill bar highlighting risky elements.
  - Animated SVG circular Risk Gauge (0-100).
  - High-contrast dark theme by default with light theme toggle.
  - Accessible design with WCAG AA compliance, inline SVGs, and ARIA live regions.
  - Freeform SMS / email body scanner with HTML anchor text mismatch detection.
  - Session scan history stored in `localStorage`.
