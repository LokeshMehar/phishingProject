/**
 * Rule: Suspicious / Abuse-Prone Top-Level Domain (TLD)
 * 
 * Certain top-level domains (.xyz, .top, .click, .loan, .zip, etc.) have historically
 * high abuse rates and low registration costs, making them popular for bulk disposable phishing kits.
 * 
 * IMPORTANT: This is intentionally treated as a WEAK signal (weight 15).
 * It will NEVER trigger a "Phishing" verdict on its own.
 */

import { ENGINE_CONFIG } from '../config.js';
import { tlds as suspiciousTlds } from '../../data/index.js';

export const suspiciousTldRule = {
  id: 'suspicious-tld',
  title: 'High-Abuse Top-Level Domain (TLD)',
  severity: ENGINE_CONFIG.severities.LOW,
  weight: ENGINE_CONFIG.weights['suspicious-tld'],

  /**
   * @param {object} parsedUrl 
   * @returns {{ triggered: boolean, evidence?: string, riskySegment?: string }}
   */
  check(parsedUrl) {
    if (!parsedUrl || !parsedUrl.valid || !parsedUrl.tld) {
      return { triggered: false };
    }

    const tld = parsedUrl.tld.toLowerCase();
    if (suspiciousTlds.includes(tld)) {
      return {
        triggered: true,
        evidence: `Domain utilizes '.${tld}', a top-level domain frequently observed in low-cost disposable phishing infrastructure`,
        riskySegment: 'registrableDomain'
      };
    }

    return { triggered: false };
  },

  explanation: 'Certain top-level domain extensions (.xyz, .top, .click, .work, .zip) have extremely low registration fees and minimal verification, leading to disproportionate abuse in mass phishing campaigns.',
  advice: 'Legitimate organizations occasionally use alternative TLDs, but sensitive login and banking portals rarely do. Exercise increased scrutiny if prompted for personal data.'
};
