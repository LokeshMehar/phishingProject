/**
 * PhishGuard Detection Engine Configuration
 * 
 * All severity definitions, rule base weights, threshold cutoffs,
 * dampening factors, and combination bonuses are centralized here.
 * 
 * Philosophy:
 * - Deterministic, explainable scoring (0 - 100).
 * - No single weak indicator (e.g. suspicious TLD alone or plain HTTP alone)
 *   should ever trigger a "Phishing" verdict on its own.
 * - High-confidence structural anomalies (IP hosts, userinfo @ tricks,
 *   brand impersonation) carry decisive weight.
 * - Legitimate allow-listed domains receive dampening on generic keywords
 *   (e.g., accounts.google.com/login is normal web behavior).
 */

export const ENGINE_CONFIG = {
  // Score thresholds mapping composite score (0-100) to human-readable verdicts
  thresholds: {
    safeMax: 24,       // 0 - 24: Safe (benign/standard traffic)
    suspiciousMax: 59, // 25 - 59: Suspicious (caution warranted, anomalous indicators)
    phishingMin: 60    // 60 - 100: Phishing (high-confidence threat)
  },

  // Base rule weights by rule identifier
  weights: {
    'ip-host': 55,             // Direct IP host without hostname is a classic evasion/c2 pattern
    'userinfo': 65,            // Using userinfo (@) to hide the real destination host is almost always malicious
    'brand-impersonation': 50, // Deceptive brand token in subdomain, path, or hyphenated host
    'typosquatting': 45,       // Damerau-Levenshtein distance 1-2 from genuine brand domain
    'homograph-idn': 50,       // Punycode (xn--) or Cyrillic/Greek lookalikes impersonating Latin brands
    'subdomain-depth': 20,     // Excessive subdomains (>3 levels) or heavy hyphen/digit stuffing
    'suspicious-tld': 15,      // Known abuse-prone TLD (weak signal; never sufficient on its own)
    'url-shortener': 15,       // URL shortener concealing actual endpoint (weak/contextual signal)
    'credential-keywords': 15, // Login/verify/account keywords (low alone, potent in combination)
    'insecure-scheme': 15,     // Plain HTTP or dangerous schemes (javascript:, data:)
    'url-structure': 20        // Non-standard port, excessive length, double-slash redirect evasion
  },

  // Severity labels assigned to rule hits
  severities: {
    CRITICAL: 'critical',
    HIGH: 'high',
    MEDIUM: 'medium',
    LOW: 'low',
    INFO: 'info'
  },

  // Combination bonuses rewarded when correlated risk factors co-occur
  combinations: [
    {
      rules: ['brand-impersonation', 'credential-keywords'],
      bonus: 15,
      reason: 'Brand impersonation combined with credential harvesting keywords indicates targeted phishing'
    },
    {
      rules: ['brand-impersonation', 'suspicious-tld'],
      bonus: 15,
      reason: 'Brand impersonation hosted on a known abuse-prone TLD is a strong indicator of disposable attack infrastructure'
    },
    {
      rules: ['typosquatting', 'credential-keywords'],
      bonus: 15,
      reason: 'Typosquatted domain hosting a credential login or verification page'
    },
    {
      rules: ['ip-host', 'credential-keywords'],
      bonus: 20,
      reason: 'Bare IP address hosting credential collection endpoints'
    },
    {
      rules: ['url-shortener', 'credential-keywords'],
      bonus: 10,
      reason: 'Shortened redirect link masking a credential authentication target'
    }
  ],

  // Dampening factors for allow-listed domains
  allowlistDampening: {
    // When a domain is in the verified allow-list and does NOT have deceptive userinfo (@) or homographs:
    // Dampens cosmetic flags like legitimate login keywords or deep subdomains to 0
    dampenCosmeticRules: ['credential-keywords', 'subdomain-depth', 'url-structure'],
    // Caps the max score for genuine allow-listed domains to prevent false positives
    maxScore: 10
  }
};
