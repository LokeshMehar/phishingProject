/**
 * PhishGuard URL Parser & Registrable Domain Extractor
 * 
 * Provides robust URL normalization, safe parsing via standard URL class,
 * public suffix matching (eTLD+1), and segment breakdown for explainable UI rendering.
 */

import { suffixes as defaultSuffixes } from '../data/index.js';

// Pre-sort suffixes by length descending so multi-part suffixes (e.g. 'co.uk') match before ('uk')
const sortedSuffixes = [...defaultSuffixes].sort((a, b) => b.length - a.length);

/**
 * Checks if a string represents an IPv4 address in decimal dotted, hex, octal, or single integer format.
 * @param {string} host 
 * @returns {{ isIp: boolean, type: string | null }}
 */
export function detectIpHost(host) {
  if (!host) return { isIp: false, type: null };
  const cleanHost = host.trim().replace(/^\[|\]$/g, ''); // strip IPv6 brackets if any

  // IPv6 check
  if (cleanHost.includes(':')) {
    return { isIp: true, type: 'ipv6' };
  }

  // Standard dotted-decimal IPv4: 0.0.0.0 - 255.255.255.255
  const dottedIpv4Regex = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
  const dottedMatch = cleanHost.match(dottedIpv4Regex);
  if (dottedMatch) {
    const octets = dottedMatch.slice(1).map(Number);
    if (octets.every(o => o >= 0 && o <= 255)) {
      return { isIp: true, type: 'ipv4-dotted' };
    }
  }

  // Hexadecimal notation: 0x7f.0x0.0x0.0x1 or single integer 0x7f000001
  if (/^0x[0-9a-f]+(\.0x[0-9a-f]+){3}$/i.test(cleanHost) || /^0x[0-9a-f]{8}$/i.test(cleanHost)) {
    return { isIp: true, type: 'ipv4-hex' };
  }

  // Octal notation: 0177.0.0.1 or 017700000001
  if (/^0[0-7]+(\.0[0-7]+){3}$/.test(cleanHost) || /^0[0-7]{11}$/.test(cleanHost)) {
    return { isIp: true, type: 'ipv4-octal' };
  }

  // Single 32-bit integer decimal: e.g. 2130706433 (127.0.0.1)
  if (/^\d{8,11}$/.test(cleanHost)) {
    const num = Number(cleanHost);
    if (num >= 0 && num <= 4294967295) {
      return { isIp: true, type: 'ipv4-decimal' };
    }
  }

  return { isIp: false, type: null };
}

/**
 * Extracts the registrable domain (eTLD+1), subdomain, and public suffix from a hostname.
 * @param {string} hostname 
 * @param {string[]} [customSuffixes]
 * @returns {{ registrableDomain: string, subdomain: string, tld: string }}
 */
export function extractDomainParts(hostname, customSuffixes = sortedSuffixes) {
  if (!hostname) {
    return { registrableDomain: '', subdomain: '', tld: '' };
  }

  const cleanHost = hostname.toLowerCase().replace(/\.+$/, ''); // strip trailing dots
  const ipCheck = detectIpHost(cleanHost);

  if (ipCheck.isIp) {
    return {
      registrableDomain: cleanHost,
      subdomain: '',
      tld: ''
    };
  }

  const parts = cleanHost.split('.');
  if (parts.length <= 1) {
    return {
      registrableDomain: cleanHost,
      subdomain: '',
      tld: cleanHost
    };
  }

  // Find longest matching public suffix
  let matchedSuffix = '';
  for (const suffix of customSuffixes) {
    const suffixParts = suffix.split('.');
    if (cleanHost === suffix || cleanHost.endsWith('.' + suffix)) {
      matchedSuffix = suffix;
      break;
    }
  }

  // If no known suffix matched, assume the last segment is the TLD
  if (!matchedSuffix) {
    matchedSuffix = parts[parts.length - 1];
  }

  const suffixPartCount = matchedSuffix.split('.').length;
  const remainingParts = parts.slice(0, parts.length - suffixPartCount);

  if (remainingParts.length === 0) {
    return {
      registrableDomain: cleanHost,
      subdomain: '',
      tld: matchedSuffix
    };
  }

  const domainLabel = remainingParts[remainingParts.length - 1];
  const registrableDomain = `${domainLabel}.${matchedSuffix}`;
  const subdomain = remainingParts.slice(0, remainingParts.length - 1).join('.');

  return {
    registrableDomain,
    subdomain,
    tld: matchedSuffix
  };
}

/**
 * Normalizes and safely parses a URL string.
 * @param {string} rawInput 
 * @returns {object} Parsed URL structure or error object
 */
export function parseUrl(rawInput) {
  if (typeof rawInput !== 'string') {
    return { valid: false, error: 'Input must be a string', rawInput: String(rawInput || '') };
  }

  let cleaned = rawInput.trim();
  if (!cleaned) {
    return { valid: false, error: 'Input is empty', rawInput };
  }

  // Strip wrapping quotes, brackets, or angle brackets (common when copied from logs/chat)
  cleaned = cleaned.replace(/^['"<(\[]+|['">)\]]+$/g, '').trim();

  // Detect explicit userinfo trick (@) in raw input before parsing
  // e.g. "https://paypal.com@evil-site.com" or "paypal.com:secret@evil-site.com"
  const rawUserInfoMatch = cleaned.match(/^(?:https?:\/\/)?([^/?#]+)@([^/?#]+)/i);
  const rawUserInfo = rawUserInfoMatch ? rawUserInfoMatch[1] : null;

  // Ensure scheme is present for parser
  let schemeAdded = false;
  if (cleaned.startsWith('//')) {
    cleaned = 'https:' + cleaned;
    schemeAdded = true;
  } else if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(cleaned)) {
    cleaned = 'https://' + cleaned;
    schemeAdded = true;
  }

  let parsed;
  try {
    parsed = new URL(cleaned);
  } catch (err) {
    return {
      valid: false,
      error: `Malformed URL structure: ${err.message}`,
      rawInput
    };
  }

  // Strip trailing dot from hostname (e.g. "example.com.")
  let hostname = parsed.hostname.toLowerCase().replace(/\.+$/, '');

  const ipCheck = detectIpHost(hostname);
  const { registrableDomain, subdomain, tld } = extractDomainParts(hostname);
  const isPunycode = hostname.includes('xn--');

  // Decode punycode if applicable
  let unicodeHost = hostname;
  if (isPunycode) {
    try {
      // In modern JS runtimes, URL decodes punycode or we keep host
      unicodeHost = hostname;
    } catch {
      unicodeHost = hostname;
    }
  }

  const hasUserInfo = Boolean(parsed.username || parsed.password || rawUserInfo);

  // Construct segmented visual model for UI highlighting
  const schemeFormatted = parsed.protocol ? `${parsed.protocol}//` : 'https://';
  const urlSegments = {
    scheme: schemeFormatted,
    userInfo: hasUserInfo ? (rawUserInfo ? `${rawUserInfo}@` : `${parsed.username ? parsed.username : ''}${parsed.password ? ':' + parsed.password : ''}@`) : '',
    subdomain: subdomain ? `${subdomain}.` : '',
    registrableDomain: registrableDomain || hostname,
    port: parsed.port ? `:${parsed.port}` : '',
    pathname: parsed.pathname === '/' && !cleaned.endsWith('/') ? '' : parsed.pathname,
    search: parsed.search || '',
    hash: parsed.hash || ''
  };

  return {
    valid: true,
    rawInput,
    normalizedUrl: parsed.href,
    scheme: parsed.protocol.replace(':', ''),
    schemeAdded,
    hostname,
    unicodeHost,
    port: parsed.port,
    pathname: parsed.pathname,
    search: parsed.search,
    hash: parsed.hash,
    username: parsed.username || (rawUserInfo ? rawUserInfo.split(':')[0] : ''),
    password: parsed.password || (rawUserInfo && rawUserInfo.includes(':') ? rawUserInfo.split(':')[1] : ''),
    hasUserInfo,
    subdomain,
    registrableDomain,
    tld,
    isIp: ipCheck.isIp,
    ipType: ipCheck.type,
    isPunycode,
    urlSegments
  };
}
