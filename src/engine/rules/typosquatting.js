/**
 * Rule: Typosquatting Detection (Damerau-Levenshtein Distance)
 * 
 * Computes edit distance between the candidate domain label and high-value brand names.
 * Detects common keyboard mis-types, omits, additions, substitutions (e.g. paypa1, goolge, arnazon)
 * with strict length guards to prevent false positives on naturally short domains.
 */

import { ENGINE_CONFIG } from '../config.js';
import { brands } from '../../data/index.js';

/**
 * Computes Damerau-Levenshtein distance between two strings.
 * Accounts for insertions, deletions, substitutions, and transpositions.
 * @param {string} a 
 * @param {string} b 
 * @returns {number}
 */
export function damerauLevenshtein(a, b) {
  if (a === b) return 0;
  if (!a.length) return b.length;
  if (!b.length) return a.length;

  const lenA = a.length;
  const lenB = b.length;
  const d = Array.from({ length: lenA + 1 }, () => new Array(lenB + 1).fill(0));

  for (let i = 0; i <= lenA; i++) d[i][0] = i;
  for (let j = 0; j <= lenB; j++) d[0][j] = j;

  for (let i = 1; i <= lenA; i++) {
    for (let j = 1; j <= lenB; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      d[i][j] = Math.min(
        d[i - 1][j] + 1,       // deletion
        d[i][j - 1] + 1,       // insertion
        d[i - 1][j - 1] + cost // substitution
      );

      // Transposition check
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
      }
    }
  }

  return d[lenA][lenB];
}

export const typosquattingRule = {
  id: 'typosquatting',
  title: 'Typosquatting & Deceptive Lookalike Domain',
  severity: ENGINE_CONFIG.severities.HIGH,
  weight: ENGINE_CONFIG.weights['typosquatting'],

  /**
   * @param {object} parsedUrl 
   * @returns {{ triggered: boolean, evidence?: string, riskySegment?: string, targetBrand?: string }}
   */
  check(parsedUrl) {
    if (!parsedUrl || !parsedUrl.valid || !parsedUrl.registrableDomain) {
      return { triggered: false };
    }

    const { registrableDomain } = parsedUrl;
    const domainLabel = registrableDomain.split('.')[0].toLowerCase();

    // Guard: ignore very short domain labels (< 5 chars) to prevent false positives
    if (domainLabel.length < 5) {
      return { triggered: false };
    }

    for (const item of brands) {
      const brandToken = item.brand.toLowerCase();

      // Skip exact match (exact match on legitimate domain is handled by allow-list / brand-impersonation)
      if (domainLabel === brandToken) {
        continue;
      }

      // Length guard on brand token
      if (brandToken.length < 5) {
        continue;
      }

      const dist = damerauLevenshtein(domainLabel, brandToken);

      // Distance 1: typosquat (e.g., 'paypa1' vs 'paypal', 'goolge' vs 'google', 'netflx' vs 'netflix')
      // Distance 2: allowed only if length is 7+ chars to avoid excessive drift
      const isSquat = (dist === 1) || (dist === 2 && domainLabel.length >= 7 && brandToken.length >= 7);

      if (isSquat) {
        return {
          triggered: true,
          evidence: `Domain '${registrableDomain}' appears to typosquat brand '${item.name}' (edit distance ${dist} from '${brandToken}')`,
          riskySegment: 'registrableDomain',
          targetBrand: item.name
        };
      }
    }

    return { triggered: false };
  },

  explanation: 'Typosquatting targets users who mis-type popular website addresses or do not look closely at a link. Attackers register domains differing by only 1 or 2 characters from authentic brand names.',
  advice: 'Carefully verify the spelling of the domain name. Do not rely on visual memory for complex or high-risk accounts; bookmark authentic sites or type their addresses directly.'
};
