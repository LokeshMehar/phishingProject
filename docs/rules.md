# PhishGuard Detection Rules Catalog

PhishGuard employs 11 deterministic, modular heuristic rules to inspect URLs for phishing threats. Every rule is implemented as an isolated ES module within `src/engine/rules/`.

---

### 1. `ip-host` (Direct IP Address Used as Hostname)
- **Weight**: 55 | **Severity**: High
- **What it detects**: Dotted IPv4 (e.g. `192.168.1.1`), hexadecimal (e.g. `0x7f000001`), octal (`017700000001`), 32-bit decimal integer (`2130706433`), and IPv6 addresses used directly in the host portion of a URL.
- **Why it is risky**: Genuine businesses host public services on DNS domain names. Attackers use bare IP hosts to evade domain registration takedowns and avoid reputation scoring on newly registered domains.
- **Example**: `http://192.168.1.50/login.php`
- **Limitations**: Internal intranet pages or developer endpoints (e.g. `127.0.0.1`) use IP addresses. Local loopback addresses are treated as low risk unless non-standard ports or suspicious paths are present.

---

### 2. `userinfo` (Deceptive User Authentication Trick)
- **Weight**: 65 | **Severity**: Critical
- **What it detects**: The `@` character in the authority segment of a URL (e.g. `https://paypal.com@attacker-site.com`).
- **Why it is risky**: RFC 3986 specifies that text before `@` represents login credentials (`user:password@host`). Web browsers ignore the text before `@` and navigate to the domain *after* the `@`. Attackers exploit this visual deception to make victims think they are visiting a trusted service.
- **Example**: `https://paypal.com@evil-site.com/signin`
- **Limitations**: Very rare legacy FTP or developer internal tools use `user:pass@host`. Modern web standards discourage credentials in URLs.

---

### 3. `brand-impersonation` (Brand Trademark Impersonation)
- **Weight**: 50 | **Severity**: Critical
- **What it detects**: Well-known brand trademarks (from `brands.json`, containing 70+ top targets) appearing in subdomains (e.g. `paypal.com.secure-update.xyz`), compound hyphenated domains (`chase-security-update.com`), or credential paths on unaffiliated domains.
- **Why it is risky**: Criminals cannot register the authentic domain (`paypal.com`), so they embed the brand name into subdomains or hyphenated lookalikes to manipulate visual trust.
- **Example**: `http://paypal.com.secure-login.xyz/verify`
- **Verification / Anti-False Positive**: Verified against the brand's genuine registrable domains (`google.com`, `amazon.in`, `apple.com`). Genuine subdomains (e.g. `accounts.google.com`, `aws.amazon.com`) never trigger this rule.

---

### 4. `typosquatting` (Typosquatting & Deceptive Lookalike Domain)
- **Weight**: 45 | **Severity**: High
- **What it detects**: Registrable domain labels having a Damerau-Levenshtein edit distance of 1 (or 2 for longer strings) from a high-profile brand domain.
- **Why it is risky**: Exploit common keyboard mis-types (omissions, transpositions, substitutions) or visual similarities to trick users.
- **Example**: `http://paypa1.com/login` (distance 1 from `paypal`), `http://goolge.com`
- **Limitations**: Strict length guards (minimum 5 characters) prevent false positives on short dictionary words (e.g. `cat.org` vs `citi`).

---

### 5. `homograph-idn` (Homograph & Punycode IDN Visual Spoofing)
- **Weight**: 50 | **Severity**: High
- **What it detects**: Punycode domains (`xn--`), non-Latin Cyrillic/Greek lookalikes, and leetspeak visual substitutions (`rn` for `m`, `0` for `o`).
- **Why it is risky**: Characters from non-Latin alphabets render identically to Latin characters on modern screens (e.g. Cyrillic 'а' U+0430 vs Latin 'a' U+0061), causing users to believe they are on the real domain.
- **Example**: `http://xn--pple-43d.com/signin` (Punycode spoof of `apple.com`)
- **Limitations**: Legitimate non-English international websites use IDN. PhishGuard flags IDN specifically when spoofing Latin trademarks or when combined with suspicious TLDs.

---

### 6. `subdomain-depth` (Excessive Subdomain Depth & Host Padding)
- **Weight**: 20 | **Severity**: Medium
- **What it detects**: Hostnames with more than 3 subdomain levels, 3+ hyphens in the hostname, or unusually long sequences of digits in the domain.
- **Why it is risky**: Attackers construct deep subdomains to pack keywords and push the actual destination domain off-screen on mobile viewports.
- **Example**: `http://a.b.c.d.secure-login-account-update.xyz/verify`
- **Limitations**: Complex enterprise CDNs (e.g. `us-east-1.console.aws.amazon.com`) use multi-level subdomains; on allow-listed domains, this signal is dampened.

---

### 7. `suspicious-tld` (High-Abuse Top-Level Domain)
- **Weight**: 15 | **Severity**: Low (Weak Signal)
- **What it detects**: Domains registered under top-level extensions with historically elevated rates of disposable phishing registrations (`.xyz`, `.top`, `.click`, `.loan`, `.work`, `.zip`, `.mov`).
- **Why it is risky**: Low registration costs and minimal KYC checks make these extensions attractive for short-lived attack campaigns.
- **Important**: This is explicitly weighted as a weak signal. It will **never** cause a "Phishing" verdict on its own.
- **Example**: `http://update-portal.xyz`

---

### 8. `url-shortener` (Obfuscated Destination via URL Shortener)
- **Weight**: 15 | **Severity**: Low
- **What it detects**: Hostnames matching popular public shortening services (`bit.ly`, `tinyurl.com`, `t.co`, `is.gd`, `cutt.ly`).
- **Why it is risky**: URL shorteners mask the true landing destination, preventing email gateways and users from inspecting the domain prior to clicking.
- **Example**: `https://bit.ly/3xYzA1`

---

### 9. `credential-keywords` (Authentication & Credential Collection Keywords)
- **Weight**: 15 | **Severity**: Low
- **What it detects**: Sensitive keywords (`login`, `signin`, `verify`, `account`, `wallet`, `security`, `password`) in the domain, subdomain, or path.
- **Why it is risky**: Phishing campaigns almost always guide victims toward credential input fields.
- **Important**: Genuine login portals (`accounts.google.com/signin`) use these paths normally. When detected on allow-listed domains, this rule is dampened to 0.

---

### 10. `insecure-scheme` (Insecure Protocol or Dangerous URI Scheme)
- **Weight**: 15 (HTTP) / 60 (Dangerous) | **Severity**: Low to Critical
- **What it detects**: Plaintext unencrypted `http://`, or dangerous client-side executable pseudo-protocols (`javascript:`, `data:`).
- **Why it is risky**: `javascript:` executes arbitrary code; `data:` renders client-side phishing pages.
- **Defensive Principle**: Over 80% of modern phishing pages use valid HTTPS certificates. Therefore, HTTPS **never** reduces the risk score; only plain HTTP or executable protocols increase it.

---

### 11. `url-structure` (Anomalous URL Structure & Evasion Techniques)
- **Weight**: 20 | **Severity**: Medium
- **What it detects**: Non-standard network ports (`:8080`, `:2082`, `:8443`), excessive URL length (> 120 characters), heavy percent-encoding (`%20`, `%2e`), and double-slash redirect sequences (`//`).
- **Why it is risky**: Phishers use non-standard ports to host rogue web servers, inflate URL length to conceal destinations on mobile screens, and use percent-encoding to evade simple text filters.
- **Example**: `http://example.xyz:2082/login`
