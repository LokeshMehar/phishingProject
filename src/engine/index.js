/**
 * PhishGuard Detection Engine Public API
 * 
 * Side-effect-free, deterministic phishing analysis engine.
 * Exported functions:
 * - analyze(input): Analyze a URL or text input
 * - analyzeUrl(urlStr): Pure URL analysis
 * - analyzeText(textStr): Text / SMS / Email snippet analysis
 */

import { parseUrl } from './parser.js';
import { scoreParsedUrl } from './scoring.js';
import { lexicon } from '../data/index.js';
import { ENGINE_CONFIG } from './config.js';

/**
 * Analyzes a URL string.
 * @param {string} urlString 
 * @returns {object} Analysis report
 */
export function analyzeUrl(urlString) {
  const parsed = parseUrl(urlString);

  if (!parsed.valid) {
    return {
      input: urlString,
      type: 'url',
      valid: false,
      score: 0,
      verdict: 'Invalid',
      verdictColor: 'warning',
      error: parsed.error,
      evidence: [],
      combinationBonuses: [],
      dampenedRules: [],
      urlSegments: null,
      primaryRiskSegment: null,
      summary: parsed.error
    };
  }

  const scored = scoreParsedUrl(parsed);

  return {
    input: urlString,
    type: 'url',
    valid: true,
    score: scored.score,
    verdict: scored.verdict,
    verdictColor: scored.verdictColor,
    isAllowlisted: scored.isAllowlisted,
    parsedUrl: parsed,
    urlSegments: parsed.urlSegments,
    primaryRiskSegment: scored.primaryRiskSegment,
    evidence: scored.triggeredRules,
    combinationBonuses: scored.combinationBonuses,
    dampenedRules: scored.dampenedRules,
    summary: scored.summary
  };
}

/**
 * Analyzes freeform text (SMS, email body, or messages) for phishing indicators.
 * Extracts embedded URLs, evaluates urgency/psychological triggers, and detects link text/href mismatches.
 * @param {string} textContent 
 * @returns {object} Analysis report
 */
export function analyzeText(textContent) {
  if (typeof textContent !== 'string' || !textContent.trim()) {
    return {
      input: textContent,
      type: 'text',
      valid: false,
      score: 0,
      verdict: 'Invalid',
      verdictColor: 'warning',
      summary: 'Input text is empty',
      urls: [],
      psychologicalTriggers: [],
      htmlMismatches: []
    };
  }

  const rawText = textContent.trim();
  const lowerText = rawText.toLowerCase();

  // 1. Detect HTML anchor tag mismatches: <a href="evil.com">legit.com</a>
  const htmlMismatches = [];
  const anchorRegex = /<a\s+(?:[^>]*?\s+)?href=(["'])(.*?)\1[^>]*>(.*?)<\/a>/gi;
  let anchorMatch;
  while ((anchorMatch = anchorRegex.exec(rawText)) !== null) {
    const href = anchorMatch[2].trim();
    const visibleText = anchorMatch[3].replace(/<[^>]*>/g, '').trim();

    // Check if visible text looks like a URL or domain but differs from destination
    if (/^[a-z0-9.-]+\.[a-z]{2,}/i.test(visibleText) || visibleText.startsWith('http')) {
      const parsedHref = parseUrl(href);
      const parsedVisible = parseUrl(visibleText);
      if (parsedHref.valid && parsedVisible.valid) {
        if (parsedHref.registrableDomain !== parsedVisible.registrableDomain) {
          htmlMismatches.push({
            visibleText,
            actualHref: href,
            evidence: `Deceptive hyperlink: visible text shows '${visibleText}' but actually navigates to '${parsedHref.registrableDomain}'`
          });
        }
      }
    }
  }

  // 2. Extract URLs from text
  const urlRegex = /(https?:\/\/[^\s<>"'\)]+|(?<!@)(?:[a-z0-9-]+\.)+[a-z]{2,}(?:\/[^\s<>"'\)]*)?)/gi;
  const rawUrls = (rawText.match(urlRegex) || []).map(u => u.replace(/[.,;!?]+$/, ''));
  const uniqueUrls = [...new Set(rawUrls)];

  const analyzedUrls = uniqueUrls.map(u => analyzeUrl(u));

  // 3. Match psychological urgency, threat, or reward language from lexicon
  const matchedTriggers = [];
  for (const [category, keywords] of Object.entries(lexicon)) {
    for (const kw of keywords) {
      if (lowerText.includes(kw.toLowerCase())) {
        matchedTriggers.push({
          category,
          keyword: kw,
          evidence: `Suspicious psychological trigger ('${kw}') commonly found in ${category} phishing communications`
        });
      }
    }
  }

  // Calculate composite text score
  let textScore = 0;
  const highestUrlScore = analyzedUrls.length > 0
    ? Math.max(...analyzedUrls.map(u => u.score))
    : 0;

  textScore += highestUrlScore;

  // Add weight for urgency triggers (capped at 30 points)
  const triggerWeight = Math.min(matchedTriggers.length * 10, 30);
  textScore += triggerWeight;

  // Add critical weight for HTML anchor spoofing
  if (htmlMismatches.length > 0) {
    textScore += 50;
  }

  textScore = Math.min(Math.max(textScore, 0), 100);

  let verdict = 'Safe';
  let verdictColor = 'success';
  if (textScore >= ENGINE_CONFIG.thresholds.phishingMin) {
    verdict = 'Phishing';
    verdictColor = 'danger';
  } else if (textScore > ENGINE_CONFIG.thresholds.safeMax) {
    verdict = 'Suspicious';
    verdictColor = 'warning';
  }

  const summary = verdict === 'Phishing'
    ? `Text contains high-risk phishing elements (${analyzedUrls.length} links found, ${matchedTriggers.length} urgency triggers).`
    : verdict === 'Suspicious'
    ? `Potential social engineering indicators detected. Proceed with caution.`
    : `No prominent phishing threats identified in provided text.`;

  // Add combined evidence for text analysis
  const combinedEvidence = [
    ...analyzedUrls.flatMap(u => u.evidence || []),
    ...matchedTriggers.map(t => ({ id: `trigger-${t.category}`, title: `Psychological Trigger: ${t.category}`, evidence: t.evidence, severity: 'medium' })),
    ...htmlMismatches.map(m => ({ id: 'html-anchor-spoof', title: 'Hyperlink Text vs Destination Mismatch', evidence: m.evidence, severity: 'critical' }))
  ];

  return {
    input: rawText,
    type: 'text',
    valid: true,
    score: textScore,
    verdict,
    verdictColor,
    evidence: combinedEvidence,
    analyzedUrls,
    matchedTriggers,
    htmlMismatches,
    summary
  };
}

/**
 * Universal analysis entry point. Automatically routes input.
 * @param {string} input 
 * @returns {object} Analysis result
 */
export function analyze(input) {
  if (typeof input !== 'string') {
    return analyzeUrl('');
  }

  const trimmed = input.trim();
  // If it's a single line and looks like a URL or single token, analyze as URL
  const isSingleLine = !trimmed.includes('\n');
  const isLikelyUrl = isSingleLine && (
    /^[a-zA-Z][a-zA-Z0-9+.-]*:/i.test(trimmed) ||
    /^[a-z0-9.-]+\.[a-z]{2,}/i.test(trimmed) ||
    /^\d{1,3}\.\d{1,3}/.test(trimmed) ||
    trimmed.startsWith('//')
  );

  if (isLikelyUrl && (!trimmed.includes(' ') || /^(javascript|data):/i.test(trimmed))) {
    return analyzeUrl(trimmed);
  }

  // Otherwise analyze as freeform text / message
  return analyzeText(trimmed);
}

export { parseUrl, scoreParsedUrl, ENGINE_CONFIG };
