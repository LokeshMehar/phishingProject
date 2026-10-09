/**
 * Rule: Brand Impersonation Detection
 * 
 * Flags URLs that incorporate well-known brand trademarks into subdomains,
 * compound domain names, or deceptive path structures when the registrable domain
 * does NOT belong to that brand's verified domains.
 * 
 * Correctly distinguishes legitimate infrastructure (accounts.google.com, www.amazon.in)
 * from attack patterns (paypal.com.secure-login.xyz, login-microsoft365.com).
 */

import { ENGINE_CONFIG } from '../config.js';
import { brands } from '../../data/index.js';

export const brandImpersonationRule = {
  id: 'brand-impersonation',
  title: 'Brand Trademark Impersonation',
  severity: ENGINE_CONFIG.severities.CRITICAL,
  weight: ENGINE_CONFIG.weights['brand-impersonation'],

  /**
   * @param {object} parsedUrl 
   * @returns {{ triggered: boolean, evidence?: string, riskySegment?: string, brandMatched?: string }}
   */
  check(parsedUrl) {
    if (!parsedUrl || !parsedUrl.valid || !parsedUrl.hostname) {
      return { triggered: false };
    }

    const { registrableDomain, subdomain, pathname, hostname } = parsedUrl;

    for (const item of brands) {
      const brandToken = item.brand.toLowerCase();
      const officialDomains = item.domains.map(d => d.toLowerCase());

      // If the registrable domain IS one of this brand's official domains, this is legitimate
      const isOfficialDomain = officialDomains.some(official => {
        return registrableDomain === official || hostname === official || hostname.endsWith('.' + official);
      });

      if (isOfficialDomain) {
        // Legitimate owner; ignore this brand for this URL
        continue;
      }

      // Check for brand name token with word boundary/delimiters to avoid substrings like 'pineapple' for 'apple'
      const tokenRegex = new RegExp(`(^|[-._0-9])${brandToken}($|[-._0-9])`, 'i');

      // Check 1: Brand appears in subdomain
      if (subdomain && (tokenRegex.test(subdomain) || subdomain.toLowerCase().includes(brandToken))) {
        return {
          triggered: true,
          evidence: `Brand '${item.name}' found in subdomain ('${subdomain}') of unaffiliated domain '${registrableDomain}'`,
          riskySegment: 'subdomain',
          brandMatched: item.name
        };
      }

      // Check 2: Brand appears as part of an unaffiliated registrable domain name
      // e.g. "paypal-security.com", "verify-apple-id.net"
      const domainLabel = registrableDomain.split('.')[0];
      if (tokenRegex.test(domainLabel)) {
        return {
          triggered: true,
          evidence: `Brand '${item.name}' impersonated in domain '${registrableDomain}' (official domains include: ${item.domains.slice(0, 2).join(', ')})`,
          riskySegment: 'registrableDomain',
          brandMatched: item.name
        };
      }

      // Check 3: Brand appears alongside credential harvesting paths on third-party domain
      if (pathname && tokenRegex.test(pathname)) {
        if (/login|signin|verify|security|account|wallet/i.test(pathname)) {
          return {
            triggered: true,
            evidence: `Brand '${item.name}' targeted in path ('${pathname}') on unaffiliated host '${hostname}'`,
            riskySegment: 'pathname',
            brandMatched: item.name
          };
        }
      }
    }

    return { triggered: false };
  },

  explanation: 'Cybercriminals register lookalike domains or create deep subdomains containing famous brand names (e.g. PayPal, Apple, Microsoft) to manipulate victims into trusting a fraudulent website.',
  advice: 'Inspect the rightmost part of the domain name before the top-level suffix. Legitimate communications from companies come directly from their official domain name, never from third-party hosts posing as them.'
};
