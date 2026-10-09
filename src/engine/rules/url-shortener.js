/**
 * Rule: URL Shortener Service
 * 
 * Flags URLs that route through public shortening services (bit.ly, tinyurl.com, t.co, is.gd).
 * Shorteners intentionally conceal the true target hostname and destination parameters.
 */

import { ENGINE_CONFIG } from '../config.js';
import { shorteners } from '../../data/index.js';

export const urlShortenerRule = {
  id: 'url-shortener',
  title: 'Obfuscated Destination via URL Shortener',
  severity: ENGINE_CONFIG.severities.LOW,
  weight: ENGINE_CONFIG.weights['url-shortener'],

  /**
   * @param {object} parsedUrl 
   * @returns {{ triggered: boolean, evidence?: string, riskySegment?: string }}
   */
  check(parsedUrl) {
    if (!parsedUrl || !parsedUrl.valid || !parsedUrl.hostname) {
      return { triggered: false };
    }

    const host = parsedUrl.hostname.toLowerCase();
    const regDomain = (parsedUrl.registrableDomain || '').toLowerCase();

    const isShortener = shorteners.some(s => s === host || s === regDomain || host.endsWith('.' + s));

    if (isShortener) {
      return {
        triggered: true,
        evidence: `Hostname '${host}' is a public URL shortening service that conceals the true landing page destination`,
        riskySegment: 'registrableDomain'
      };
    }

    return { triggered: false };
  },

  explanation: 'URL shorteners obscure the real destination host and path, preventing email gateways and users from inspecting the actual domain before clicking.',
  advice: 'Do not click shortened links in unexpected emails or SMS messages. Use a URL expansion tool or check the destination preview before proceeding.'
};
