/**
 * PhishGuard Scoring Engine & Evidence Aggregator
 * 
 * Computes deterministic, explainable risk scores (0-100) and verdicts.
 * Implements:
 * 1. Rule execution and evidence extraction
 * 2. Allow-list verification with cosmetic rule dampening
 * 3. Compound risk combination bonuses
 * 4. Verdict classification (Safe / Suspicious / Phishing)
 * 5. Visual segment threat attribution
 */

import { ENGINE_CONFIG } from './config.js';
import { ALL_RULES } from './rules/index.js';
import { allowlist } from '../data/index.js';

/**
 * Checks if a parsed URL's registrable domain is in the verified allow-list.
 * Requires exact match on registrable domain to prevent subdomain bypasses (e.g. google.com.evil.xyz).
 * @param {object} parsedUrl 
 * @returns {boolean}
 */
export function isAllowlisted(parsedUrl) {
  if (!parsedUrl || !parsedUrl.valid || !parsedUrl.registrableDomain) {
    return false;
  }
  const domain = parsedUrl.registrableDomain.toLowerCase();
  return allowlist.includes(domain);
}

/**
 * Evaluates all active rules against a parsed URL and computes final score and verdict.
 * @param {object} parsedUrl 
 * @param {object[]} [rules]
 * @returns {object} Detailed score breakdown
 */
export function scoreParsedUrl(parsedUrl, rules = ALL_RULES) {
  if (!parsedUrl || !parsedUrl.valid) {
    return {
      score: 100,
      verdict: 'Invalid',
      isAllowlisted: false,
      triggeredRules: [],
      combinationBonuses: [],
      dampenedRules: [],
      primaryRiskSegment: null,
      summary: parsedUrl?.error || 'Invalid URL format'
    };
  }

  const allowlisted = isAllowlisted(parsedUrl);
  const rawTriggered = [];
  let primaryRiskSegment = null;

  // Run each registered rule
  for (const rule of rules) {
    const result = rule.check(parsedUrl);
    if (result && result.triggered) {
      const assignedSeverity = result.severityOverride || rule.severity;
      const assignedWeight = result.weightOverride !== undefined ? result.weightOverride : rule.weight;

      rawTriggered.push({
        id: rule.id,
        title: rule.title,
        severity: assignedSeverity,
        weight: assignedWeight,
        evidence: result.evidence || 'Rule condition matched',
        explanation: rule.explanation,
        advice: rule.advice,
        riskySegment: result.riskySegment || null
      });

      // Capture primary risk segment from highest-severity rule
      if (!primaryRiskSegment && result.riskySegment) {
        primaryRiskSegment = result.riskySegment;
      }
    }
  }

  const triggeredIds = new Set(rawTriggered.map(r => r.id));
  const dampenedRules = [];
  const activeTriggered = [];

  // Critical deception checks that void allow-list protection (e.g. userinfo trick: https://google.com@phish.com)
  const hasCriticalDeception = triggeredIds.has('userinfo') || triggeredIds.has('homograph-idn');

  // Apply allow-list dampening
  for (const item of rawTriggered) {
    if (allowlisted && !hasCriticalDeception && ENGINE_CONFIG.allowlistDampening.dampenCosmeticRules.includes(item.id)) {
      dampenedRules.push({
        id: item.id,
        title: item.title,
        reason: `Dampened to 0: '${parsedUrl.registrableDomain}' is an authentic allow-listed domain`
      });
    } else {
      activeTriggered.push(item);
    }
  }

  // Base score calculation
  let baseScore = activeTriggered.reduce((sum, item) => sum + item.weight, 0);

  // Combination bonuses evaluation
  const activeIds = new Set(activeTriggered.map(r => r.id));
  const appliedBonuses = [];

  for (const combo of ENGINE_CONFIG.combinations) {
    const allMatch = combo.rules.every(rId => activeIds.has(rId));
    if (allMatch) {
      appliedBonuses.push({
        rules: combo.rules,
        bonus: combo.bonus,
        reason: combo.reason
      });
      baseScore += combo.bonus;
    }
  }

  // Cap score for verified allow-listed domains without spoofing
  if (allowlisted && !hasCriticalDeception) {
    baseScore = Math.min(baseScore, ENGINE_CONFIG.allowlistDampening.maxScore);
  }

  // Final score clamping [0, 100]
  const finalScore = Math.min(Math.max(baseScore, 0), 100);

  // Verdict determination
  let verdict = 'Safe';
  let verdictColor = 'success';
  if (finalScore >= ENGINE_CONFIG.thresholds.phishingMin) {
    verdict = 'Phishing';
    verdictColor = 'danger';
  } else if (finalScore > ENGINE_CONFIG.thresholds.safeMax) {
    verdict = 'Suspicious';
    verdictColor = 'warning';
  }

  // Plain-English summary synthesis
  let summary = '';
  if (verdict === 'Phishing') {
    summary = `High-confidence phishing indicators detected (score ${finalScore}/100). Do not interact with this destination or enter sensitive credentials.`;
  } else if (verdict === 'Suspicious') {
    summary = `Multiple anomalous risk signals identified (score ${finalScore}/100). Exercise caution before following this link.`;
  } else {
    summary = allowlisted
      ? `Verified authentic domain ('${parsedUrl.registrableDomain}') with no deceptive structures detected.`
      : `No significant phishing indicators detected (score ${finalScore}/100). Standard browsing safety rules apply.`;
  }

  // Sort triggered rules by severity (critical -> high -> medium -> low)
  const severityOrder = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
  activeTriggered.sort((a, b) => (severityOrder[b.severity] || 0) - (severityOrder[a.severity] || 0));

  return {
    score: finalScore,
    verdict,
    verdictColor,
    isAllowlisted: allowlisted,
    triggeredRules: activeTriggered,
    combinationBonuses: appliedBonuses,
    dampenedRules,
    primaryRiskSegment,
    summary
  };
}
