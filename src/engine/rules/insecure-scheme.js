/**
 * Rule: Insecure or Anomalous Scheme (HTTP, Javascript, Data)
 * 
 * Flags unencrypted HTTP and dangerous client-side execution schemes (javascript:, data:).
 * 
 * CRITICAL DEFENSIVE PRINCIPLE:
 * While plaintext HTTP is unencrypted, over 80% of modern phishing websites
 * now use valid HTTPS/TLS certificates (e.g. via Let's Encrypt or Cloudflare).
 * Therefore, HTTPS MUST NEVER reduce the risk score, and plain HTTP is treated as
 * a weak advisory signal, while executable schemes are flagged with high severity.
 */

import { ENGINE_CONFIG } from '../config.js';

export const insecureSchemeRule = {
  id: 'insecure-scheme',
  title: 'Insecure Protocol or Dangerous URI Scheme',
  severity: ENGINE_CONFIG.severities.LOW,
  weight: ENGINE_CONFIG.weights['insecure-scheme'],

  /**
   * @param {object} parsedUrl 
   * @returns {{ triggered: boolean, evidence?: string, riskySegment?: string, severityOverride?: string, weightOverride?: number }}
   */
  check(parsedUrl) {
    if (!parsedUrl || !parsedUrl.valid) {
      return { triggered: false };
    }

    const scheme = (parsedUrl.scheme || '').toLowerCase();
    const raw = (parsedUrl.rawInput || '').toLowerCase().trim();

    // Check 1: Dangerous URI schemes
    if (scheme === 'javascript' || raw.startsWith('javascript:')) {
      return {
        triggered: true,
        evidence: "Dangerous 'javascript:' pseudo-protocol detected, used to execute arbitrary script code in the browser context",
        riskySegment: 'scheme',
        severityOverride: ENGINE_CONFIG.severities.CRITICAL,
        weightOverride: 60
      };
    }

    if (scheme === 'data' || raw.startsWith('data:')) {
      return {
        triggered: true,
        evidence: "Data URI ('data:') detected, frequently used to render client-side HTML phishing forms directly in the address bar",
        riskySegment: 'scheme',
        severityOverride: ENGINE_CONFIG.severities.HIGH,
        weightOverride: 45
      };
    }

    // Check 2: Explicit plain HTTP scheme (only if explicitly specified in raw input)
    if (scheme === 'http' && raw.startsWith('http://')) {
      return {
        triggered: true,
        evidence: "Connection uses unencrypted HTTP rather than HTTPS. (Note: HTTPS provides encryption but does not guarantee authenticity)",
        riskySegment: 'scheme'
      };
    }

    return { triggered: false };
  },

  explanation: 'Plaintext HTTP transmits credentials without encryption. Be aware: having an HTTPS padlock only guarantees encrypted transit to the server; it does NOT mean the server owner is honest or trustworthy.',
  advice: 'Never enter passwords or personal data over plain HTTP. Conversely, do not assume an HTTPS padlock alone means a site is safe.'
};
