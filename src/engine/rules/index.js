/**
 * PhishGuard Rule Registry
 * 
 * Central registry of all active detection rules.
 * Each rule is an isolated, testable module exposing standard properties:
 * { id, title, severity, weight, check(parsedUrl), explanation, advice }
 */

import { ipHostRule } from './ip-host.js';
import { userinfoRule } from './userinfo.js';
import { brandImpersonationRule } from './brand-impersonation.js';
import { typosquattingRule } from './typosquatting.js';
import { homographIdnRule } from './homograph-idn.js';
import { subdomainDepthRule } from './subdomain-depth.js';
import { suspiciousTldRule } from './suspicious-tld.js';
import { urlShortenerRule } from './url-shortener.js';
import { credentialKeywordsRule } from './credential-keywords.js';
import { insecureSchemeRule } from './insecure-scheme.js';
import { urlStructureRule } from './url-structure.js';

export const ALL_RULES = [
  userinfoRule,
  brandImpersonationRule,
  typosquattingRule,
  homographIdnRule,
  ipHostRule,
  subdomainDepthRule,
  suspiciousTldRule,
  urlShortenerRule,
  credentialKeywordsRule,
  insecureSchemeRule,
  urlStructureRule
];

export {
  ipHostRule,
  userinfoRule,
  brandImpersonationRule,
  typosquattingRule,
  homographIdnRule,
  subdomainDepthRule,
  suspiciousTldRule,
  urlShortenerRule,
  credentialKeywordsRule,
  insecureSchemeRule,
  urlStructureRule
};
