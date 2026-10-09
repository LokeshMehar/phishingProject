/**
 * Rule: Userinfo / '@' Trick Detection
 * 
 * In URL syntax (RFC 3986), any text between the scheme and the '@' symbol
 * is treated as username:password authentication credentials, NOT the host.
 * Attackers exploit this to trick users: "https://paypal.com@attacker-site.com"
 * navigates entirely to "attacker-site.com", while making users believe they are visiting PayPal.
 */

import { ENGINE_CONFIG } from '../config.js';

export const userinfoRule = {
  id: 'userinfo',
  title: 'Deceptive User Authentication Trick (@ in URL Authority)',
  severity: ENGINE_CONFIG.severities.CRITICAL,
  weight: ENGINE_CONFIG.weights['userinfo'],

  /**
   * @param {object} parsedUrl 
   * @returns {{ triggered: boolean, evidence?: string, riskySegment?: string }}
   */
  check(parsedUrl) {
    if (!parsedUrl || !parsedUrl.valid) {
      return { triggered: false };
    }

    if (parsedUrl.hasUserInfo) {
      const spoofedHint = parsedUrl.username ? `'${parsedUrl.username}'` : 'credentials';
      return {
        triggered: true,
        evidence: `URL contains '@' in authority component with userinfo ${spoofedHint}. Browsers navigate to '${parsedUrl.hostname}', ignoring the deceptive text before '@'`,
        riskySegment: 'userInfo'
      };
    }

    return { triggered: false };
  },

  explanation: 'The "@" character in an address separates login credentials from the actual server destination. Attackers place trusted company names before the "@" to deceive users, while the browser actually contacts the domain after the "@".',
  advice: 'Do not click links containing an "@" symbol in the domain portion. Modern web applications do not pass user credentials in web URLs.'
};
