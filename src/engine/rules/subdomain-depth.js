/**
 * Rule: Excessive Subdomain Depth & Host Padding
 * 
 * Flags URLs that use excessive subdomains (>3 levels) or heavy hyphen/digit stuffing.
 * Attackers deliberately use deep subdomains to push the true registrable domain
 * off-screen on mobile browsers or small displays.
 */

import { ENGINE_CONFIG } from '../config.js';

export const subdomainDepthRule = {
  id: 'subdomain-depth',
  title: 'Excessive Subdomain Depth or Host Padding',
  severity: ENGINE_CONFIG.severities.MEDIUM,
  weight: ENGINE_CONFIG.weights['subdomain-depth'],

  /**
   * @param {object} parsedUrl 
   * @returns {{ triggered: boolean, evidence?: string, riskySegment?: string }}
   */
  check(parsedUrl) {
    if (!parsedUrl || !parsedUrl.valid || !parsedUrl.hostname) {
      return { triggered: false };
    }

    const { subdomain, hostname, isIp } = parsedUrl;
    if (isIp) return { triggered: false };

    const reasons = [];

    // Check 1: Deep subdomains (> 3 levels in subdomain)
    if (subdomain) {
      const subLabels = subdomain.split('.').filter(Boolean);
      if (subLabels.length >= 3) {
        reasons.push(`${subLabels.length} subdomain levels ('${subdomain}')`);
      }
    }

    // Check 2: Excessive hyphens in hostname (>= 3 hyphens indicates keyword stuffing)
    const hyphenCount = (hostname.match(/-/g) || []).length;
    if (hyphenCount >= 3) {
      reasons.push(`${hyphenCount} hyphens in hostname suggesting keyword stuffing`);
    }

    // Check 3: Excessive consecutive digits in domain label
    const domainLabel = parsedUrl.registrableDomain ? parsedUrl.registrableDomain.split('.')[0] : '';
    if (/\d{5,}/.test(domainLabel)) {
      reasons.push(`unusually long numerical sequence in domain ('${domainLabel}')`);
    }

    if (reasons.length > 0) {
      return {
        triggered: true,
        evidence: `Suspicious host structure: ${reasons.join('; ')}`,
        riskySegment: subdomain ? 'subdomain' : 'registrableDomain'
      };
    }

    return { triggered: false };
  },

  explanation: 'Phishing URLs frequently use multiple stacked subdomains or excessive hyphens to pack multiple fake trust keywords and push the actual domain off the visible address bar on mobile screens.',
  advice: 'Always read domain names from right to left before the first forward slash. The true destination is the label immediately to the left of the domain extension (.com, .org, etc.).'
};
