/**
 * Rule: Credential & Urgency Keywords in URL
 * 
 * Flags authentication and security keywords ('login', 'verify', 'secure', 'update',
 * 'account', 'confirm', 'wallet', 'signin', 'banking') in host labels or URL paths.
 * 
 * NOTE: Weighted LOW (15) on its own. Authentic websites (e.g. accounts.google.com)
 * naturally use these paths, so on allow-listed domains this rule is dampened.
 * However, when paired with typosquatting, brand impersonation, or suspicious TLDs,
 * combination bonuses amplify the overall risk score.
 */

import { ENGINE_CONFIG } from '../config.js';

const CREDENTIAL_KEYWORDS = [
  'login', 'signin', 'sign-in', 'log-in', 'verify', 'verification',
  'secure', 'security', 'update', 'account', 'confirm', 'confirmation',
  'wallet', 'banking', 'authenticate', 'password', 'recovery', 'authorize'
];

export const credentialKeywordsRule = {
  id: 'credential-keywords',
  title: 'Authentication & Credential Collection Keywords',
  severity: ENGINE_CONFIG.severities.LOW,
  weight: ENGINE_CONFIG.weights['credential-keywords'],

  /**
   * @param {object} parsedUrl 
   * @returns {{ triggered: boolean, evidence?: string, riskySegment?: string, matchedKeywords?: string[] }}
   */
  check(parsedUrl) {
    if (!parsedUrl || !parsedUrl.valid) {
      return { triggered: false };
    }

    const { hostname, pathname, search } = parsedUrl;
    const targetString = `${hostname}${pathname}${search}`.toLowerCase();

    const matched = [];
    for (const kw of CREDENTIAL_KEYWORDS) {
      // Look for keyword separated by non-alphanumeric chars or boundaries
      const regex = new RegExp(`(^|[^a-z0-9])${kw}([^a-z0-9]|$)`, 'i');
      if (regex.test(targetString)) {
        matched.push(kw);
      }
    }

    if (matched.length > 0) {
      const uniqueMatched = [...new Set(matched)];
      const segment = hostname.includes(uniqueMatched[0]) ? 'hostname' : 'pathname';
      return {
        triggered: true,
        evidence: `Credential-related keywords detected (${uniqueMatched.map(k => `'${k}'`).join(', ')}) targeting user authentication`,
        riskySegment: segment,
        matchedKeywords: uniqueMatched
      };
    }

    return { triggered: false };
  },

  explanation: 'Phishing URLs frequently include authentication keywords (such as "login", "verify", or "secure") to fabricate an appearance of legitimate security protocols.',
  advice: 'Examine whether the hosting domain is genuine before typing credentials. The presence of words like "secure" or "verify" in the web address does not mean the website itself is safe.'
};
