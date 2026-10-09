/**
 * Rule: Anomalous URL Structure & Obfuscation
 * 
 * Flags evasion techniques embedded in URL structure:
 * - Non-standard networking ports (e.g. :8080, :2082, :8888 on public hosts)
 * - Excessively long URLs (> 120 characters) used for buffer/display overflow
 * - Heavy percent-encoding abuse (%2e, %2f) designed to evade pattern filters
 * - Double-slash (//) path redirect sequences
 */

import { ENGINE_CONFIG } from '../config.js';

export const urlStructureRule = {
  id: 'url-structure',
  title: 'Anomalous URL Structure or Evasion Techniques',
  severity: ENGINE_CONFIG.severities.MEDIUM,
  weight: ENGINE_CONFIG.weights['url-structure'],

  /**
   * @param {object} parsedUrl 
   * @returns {{ triggered: boolean, evidence?: string, riskySegment?: string }}
   */
  check(parsedUrl) {
    if (!parsedUrl || !parsedUrl.valid) {
      return { triggered: false };
    }

    const { rawInput, port, pathname, hostname } = parsedUrl;
    const reasons = [];
    let riskySegment = 'pathname';

    // Check 1: Non-standard web ports on public non-localhost domains
    if (port && port !== '80' && port !== '443') {
      const isLocal = /^(localhost|127\.0\.0\.1|0\.0\.0\.0|::1)$/i.test(hostname);
      if (!isLocal) {
        reasons.push(`non-standard network port (:${port})`);
        riskySegment = 'port';
      }
    }

    // Check 2: Very long overall URL (> 120 characters)
    if (rawInput && rawInput.length > 120) {
      reasons.push(`excessive length (${rawInput.length} characters)`);
    }

    // Check 3: Encoded character abuse (multiple % encodings in path/hostname)
    const encodedMatches = (rawInput.match(/%[0-9a-fA-F]{2}/g) || []).length;
    if (encodedMatches >= 4) {
      reasons.push(`high concentration of percent-encoded characters (${encodedMatches} sequences)`);
    }

    // Check 4: Double-slash (//) redirect evasion in path
    if (pathname && (pathname.includes('//') || /^\/\//.test(pathname))) {
      reasons.push('double forward-slash sequence in path, commonly used in open redirect exploits');
    }

    if (reasons.length > 0) {
      return {
        triggered: true,
        evidence: `Obfuscated or anomalous structure detected: ${reasons.join('; ')}`,
        riskySegment
      };
    }

    return { triggered: false };
  },

  explanation: 'Phishers use non-standard ports to host temporary rogue services, inflate URL lengths to hide the domain on mobile screens, and employ percent-encoding or double slashes to bypass automated web filters.',
  advice: 'Inspect why an address points to non-standard ports or contains strange encoded characters. Official services rarely require unusual port numbers.'
};
