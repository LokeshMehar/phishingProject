/**
 * Rule: Homograph & IDN (Internationalized Domain Name) Confusable Attack Detection
 * 
 * Flags internationalized domain names (Punycode 'xn--'), mixed-script unicode spoofing,
 * and visual lookalikes (e.g. Cyrillic 'а' replacing Latin 'a', '0' replacing 'o', 'rn' replacing 'm').
 */

import { ENGINE_CONFIG } from '../config.js';
import { brands } from '../../data/index.js';

// Common visual character substitutions used in phishing
const CONFUSABLE_MAP = {
  '0': 'o',
  '1': 'l',
  '3': 'e',
  '4': 'a',
  '5': 's',
  '8': 'b',
  'vv': 'w',
  'rn': 'm',
  'cl': 'd'
};

// Common Cyrillic lookalikes mapped to Latin equivalents
const CYRILLIC_LOOKALIKES = {
  '\u0430': 'a', // Cyrillic small letter a
  '\u0435': 'e', // Cyrillic small letter ie
  '\u043E': 'o', // Cyrillic small letter o
  '\u0440': 'p', // Cyrillic small letter er
  '\u0441': 'c', // Cyrillic small letter es
  '\u0443': 'y', // Cyrillic small letter u
  '\u0445': 'x', // Cyrillic small letter ha
  '\u0456': 'i'  // Cyrillic small letter byelorussian-ukrainian i
};

/**
 * Normalizes visual confusables in a domain string.
 * @param {string} str 
 * @returns {string}
 */
export function normalizeConfusables(str) {
  let normalized = str.toLowerCase();

  // Replace Cyrillic lookalikes
  for (const [cyr, lat] of Object.entries(CYRILLIC_LOOKALIKES)) {
    normalized = normalized.replaceAll(cyr, lat);
  }

  // Replace digraphic confusables ('rn' -> 'm', 'vv' -> 'w')
  normalized = normalized.replaceAll('rn', 'm');
  normalized = normalized.replaceAll('vv', 'w');
  normalized = normalized.replaceAll('cl', 'd');

  // Replace common leetspeak substitutions
  normalized = normalized.replace(/0/g, 'o')
                         .replace(/1/g, 'l')
                         .replace(/3/g, 'e')
                         .replace(/5/g, 's');

  return normalized;
}

export const homographIdnRule = {
  id: 'homograph-idn',
  title: 'Homograph or Punycode IDN Visual Spoofing',
  severity: ENGINE_CONFIG.severities.HIGH,
  weight: ENGINE_CONFIG.weights['homograph-idn'],

  /**
   * @param {object} parsedUrl 
   * @returns {{ triggered: boolean, evidence?: string, riskySegment?: string }}
   */
  check(parsedUrl) {
    if (!parsedUrl || !parsedUrl.valid || !parsedUrl.hostname) {
      return { triggered: false };
    }

    const { hostname, registrableDomain } = parsedUrl;

    // Check 1: Punycode encoded host (xn--)
    if (parsedUrl.isPunycode || hostname.includes('xn--')) {
      return {
        triggered: true,
        evidence: `Hostname contains Punycode ('xn--'), frequently utilized in Internationalized Domain Name (IDN) homograph attacks to impersonate Latin brand names`,
        riskySegment: 'registrableDomain'
      };
    }

    // Check 2: Unicode script confusables present in raw input or host
    for (const char of hostname) {
      if (CYRILLIC_LOOKALIKES[char]) {
        return {
          triggered: true,
          evidence: `Domain contains non-Latin Cyrillic lookalike character '${char}' designed to spoof Latin script visually`,
          riskySegment: 'registrableDomain'
        };
      }
    }

    // Check 3: Leet-speak and visual digraph substitutions (rn -> m, 0 -> o) matching high-profile brands
    const domainLabel = (registrableDomain || hostname).split('.')[0];
    const normalizedLabel = normalizeConfusables(domainLabel);

    if (normalizedLabel !== domainLabel) {
      for (const item of brands) {
        const brandToken = item.brand.toLowerCase();
        if (normalizedLabel === brandToken && domainLabel !== brandToken) {
          return {
            triggered: true,
            evidence: `Domain '${registrableDomain}' uses visual confusables ('${domainLabel}') that mimic authentic brand '${item.name}' ('${brandToken}')`,
            riskySegment: 'registrableDomain'
          };
        }
      }
    }

    return { triggered: false };
  },

  explanation: 'Homograph attacks exploit characters from different alphabets (like Cyrillic) or similar-looking characters (like "rn" for "m" or "0" for "o") that look identical on a screen, tricking users into visiting a fraudulent site.',
  advice: 'Be vigilant of strange characters or unusual character combinations. If a link uses internationalized characters for a service normally written in English, treat it with extreme suspicion.'
};
