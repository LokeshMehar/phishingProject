/**
 * Rule: IP Address Host
 * 
 * Legitimate web services virtually always use DNS domain names.
 * Using a raw IP address (whether dotted decimal, octal, hex, or integer)
 * is a hallmark of phishing kits and command-and-control (C2) servers
 * aiming to bypass domain reputation blocklists.
 */

import { ENGINE_CONFIG } from '../config.js';

export const ipHostRule = {
  id: 'ip-host',
  title: 'Direct IP Address Used as Hostname',
  severity: ENGINE_CONFIG.severities.HIGH,
  weight: ENGINE_CONFIG.weights['ip-host'],

  /**
   * @param {object} parsedUrl 
   * @returns {{ triggered: boolean, evidence?: string, riskySegment?: string }}
   */
  check(parsedUrl) {
    if (!parsedUrl || !parsedUrl.valid) {
      return { triggered: false };
    }

    if (parsedUrl.isIp) {
      const typeLabel = parsedUrl.ipType ? ` (${parsedUrl.ipType})` : '';
      return {
        triggered: true,
        evidence: `Hostname '${parsedUrl.hostname}' is a raw IP address${typeLabel} rather than a registered domain name`,
        riskySegment: 'registrableDomain'
      };
    }

    return { triggered: false };
  },

  explanation: 'Phishing infrastructure frequently serves credential harvesting pages directly on numerical IP addresses to evade domain registry reputation checks and takedowns.',
  advice: 'Never enter login credentials or payment details on websites addressed by raw IP addresses. Genuine institutions always host customer services on branded domain names.'
};
