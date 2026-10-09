/**
 * PhishGuard UI Rendering Engine
 * 
 * Renders the signature segmented URL visualizer, animated SVG risk gauge,
 * evidence cards, and scan history.
 */

import { escapeHtml, ICONS } from './dom.js';

/**
 * Renders an animated SVG circular Risk Gauge.
 * @param {number} score 0-100
 * @param {string} verdict 'Safe' | 'Suspicious' | 'Phishing'
 * @returns {string} HTML string
 */
export function renderRiskGauge(score, verdict) {
  const radius = 64;
  const circumference = 2 * Math.PI * radius;
  // Fill percentage
  const strokeDashoffset = circumference - (circumference * (score / 100));

  let strokeColor = 'var(--color-safe)';
  let iconSvg = ICONS.shieldCheck;
  if (verdict === 'Phishing') {
    strokeColor = 'var(--color-phishing)';
    iconSvg = ICONS.shieldAlert;
  } else if (verdict === 'Suspicious') {
    strokeColor = 'var(--color-suspicious)';
    iconSvg = ICONS.alertTriangle;
  }

  return `
    <div class="gauge-card">
      <div style="position: relative; width: 160px; height: 160px; display: flex; align-items: center; justify-content: center;">
        <svg width="160" height="160" viewBox="0 0 160 160" style="transform: rotate(-90deg);">
          <circle
            cx="80"
            cy="80"
            r="${radius}"
            stroke="var(--color-border-subtle)"
            stroke-width="12"
            fill="transparent"
          />
          <circle
            cx="80"
            cy="80"
            r="${radius}"
            stroke="${strokeColor}"
            stroke-width="12"
            stroke-linecap="round"
            stroke-dasharray="${circumference}"
            stroke-dashoffset="${strokeDashoffset}"
            fill="transparent"
            style="transition: stroke-dashoffset 0.6s cubic-bezier(0.4, 0, 0.2, 1), stroke 0.3s ease;"
          />
        </svg>
        <div style="position: absolute; display: flex; flex-direction: column; align-items: center;">
          <span style="font-size: 2.5rem; font-weight: 800; font-family: var(--font-mono); line-height: 1;">${score}</span>
          <span style="font-size: 0.72rem; text-transform: uppercase; color: var(--color-text-muted); font-weight: 600; letter-spacing: 0.05em; margin-top: 2px;">Risk Score / 100</span>
        </div>
      </div>
      <div class="verdict-tag status-${verdict}">
        ${iconSvg}
        <span>${escapeHtml(verdict)}</span>
      </div>
    </div>
  `;
}

/**
 * SIGNATURE ELEMENT: Renders the analysed URL broken into labelled segments,
 * highlighting the primary risky segment.
 * @param {object} segments 
 * @param {string} primaryRiskSegment 
 * @param {string} verdict 
 * @returns {string} HTML string
 */
export function renderUrlSegments(segments, primaryRiskSegment, verdict) {
  if (!segments) return '';

  const isThreat = verdict === 'Phishing' || verdict === 'Suspicious';
  const highlightClass = isThreat ? (verdict === 'Phishing' ? 'danger-highlight' : 'warning-highlight') : '';

  const pill = (label, value, segmentKey) => {
    if (!value) return '';
    const isRisky = isThreat && (primaryRiskSegment === segmentKey || (segmentKey === 'registrableDomain' && primaryRiskSegment === 'hostname'));
    return `
      <div class="segment-pill ${isRisky ? highlightClass : ''}" title="${isRisky ? 'Flagged as high-risk segment' : ''}">
        <span class="segment-label">${escapeHtml(label)}</span>
        <span class="segment-value">${escapeHtml(value)}</span>
      </div>
    `;
  };

  return `
    <div class="url-visualizer-card">
      <div class="visualizer-title">
        <span>Architectural URL Decomposition</span>
        ${primaryRiskSegment && isThreat ? `<span style="color: var(--color-phishing); font-size: 0.75rem;">Anomalous Segment: [${escapeHtml(primaryRiskSegment)}]</span>` : ''}
      </div>
      <div class="url-segments-strip">
        ${pill('Scheme', segments.scheme, 'scheme')}
        ${pill('Auth / @', segments.userInfo, 'userInfo')}
        ${pill('Subdomain', segments.subdomain, 'subdomain')}
        ${pill('Registrable Domain', segments.registrableDomain, 'registrableDomain')}
        ${pill('Port', segments.port, 'port')}
        ${pill('Path', segments.pathname, 'pathname')}
        ${pill('Query', segments.search, 'search')}
        ${pill('Hash', segments.hash, 'hash')}
      </div>
    </div>
  `;
}

/**
 * Renders the ranked evidence timeline.
 * @param {object[]} evidence 
 * @param {object[]} bonuses 
 * @param {object[]} dampened 
 * @returns {string} HTML string
 */
export function renderEvidenceList(evidence, bonuses = [], dampened = []) {
  if (!evidence || evidence.length === 0) {
    return `
      <div class="card" style="padding: var(--space-6); text-align: center; color: var(--color-safe);">
        <div style="margin-bottom: var(--space-2);">${ICONS.checkCircle}</div>
        <h3 style="font-size: 1.05rem; font-weight: 600;">No Threat Signals Triggered</h3>
        <p style="font-size: 0.88rem; color: var(--color-text-secondary); margin-top: 4px;">
          The parsed structure conforms to standard web patterns with no brand impersonation or evasion techniques detected.
        </p>
      </div>
    `;
  }

  const itemsHtml = evidence.map(item => `
    <div class="evidence-card sev-${item.severity}">
      <div class="evidence-header">
        <span class="evidence-title">${escapeHtml(item.title)}</span>
        <span class="sev-badge sev-${item.severity}">${escapeHtml(item.severity)} (+${item.weight} pts)</span>
      </div>
      <div class="evidence-desc">${escapeHtml(item.evidence)}</div>
      <p style="font-size: 0.85rem; color: var(--color-text-secondary); margin-bottom: var(--space-2);">
        ${escapeHtml(item.explanation)}
      </p>
      <div class="evidence-advice">
        ${ICONS.info}
        <div><strong>Actionable Advice:</strong> ${escapeHtml(item.advice)}</div>
      </div>
    </div>
  `).join('');

  const bonusesHtml = bonuses.length > 0 ? `
    <div class="card" style="background-color: var(--color-bg-subtle); border-left: 4px solid var(--color-phishing); margin-top: var(--space-4);">
      <h4 style="font-size: 0.95rem; font-weight: 600; margin-bottom: var(--space-2); color: var(--color-phishing);">
        Correlated Combination Amplification (+${bonuses.reduce((a, b) => a + b.bonus, 0)} pts)
      </h4>
      <ul style="list-style: none; padding-left: 0; font-size: 0.85rem; color: var(--color-text-secondary);">
        ${bonuses.map(b => `<li style="margin-bottom: 4px;">• <strong>+${b.bonus} pts:</strong> ${escapeHtml(b.reason)}</li>`).join('')}
      </ul>
    </div>
  ` : '';

  const dampenedHtml = dampened.length > 0 ? `
    <div class="card" style="background-color: var(--color-bg-subtle); border-left: 4px solid var(--color-safe); margin-top: var(--space-4);">
      <h4 style="font-size: 0.95rem; font-weight: 600; margin-bottom: var(--space-2); color: var(--color-safe);">
        Allow-List Dampened Signals (Suppressed False Positives)
      </h4>
      <ul style="list-style: none; padding-left: 0; font-size: 0.85rem; color: var(--color-text-secondary);">
        ${dampened.map(d => `<li style="margin-bottom: 4px;">• <strong>${escapeHtml(d.title)}:</strong> ${escapeHtml(d.reason)}</li>`).join('')}
      </ul>
    </div>
  ` : '';

  return `
    <div class="evidence-section">
      <h3 style="font-size: 1.1rem; font-weight: 600; margin-bottom: var(--space-2);">
        Ranked Forensic Evidence (${evidence.length} Indicators)
      </h3>
      ${itemsHtml}
      ${bonusesHtml}
      ${dampenedHtml}
    </div>
  `;
}

/**
 * Renders the results for Text / Message / SMS analysis.
 * @param {object} result 
 * @returns {string} HTML string
 */
export function renderTextAnalysis(result) {
  const { analyzedUrls, matchedTriggers, htmlMismatches } = result;

  const urlSection = analyzedUrls.length > 0 ? `
    <div style="margin-bottom: var(--space-6);">
      <h4 style="font-size: 1rem; font-weight: 600; margin-bottom: var(--space-3);">
        Embedded Links Extracted (${analyzedUrls.length})
      </h4>
      <div style="display: flex; flex-direction: column; gap: var(--space-3);">
        ${analyzedUrls.map(u => `
          <div style="background-color: var(--color-bg-subtle); padding: var(--space-3) var(--space-4); border-radius: var(--radius-md); border: 1px solid var(--color-border-subtle); display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: var(--space-2);">
            <div style="font-family: var(--font-mono); font-size: 0.88rem; word-break: break-all;">
              ${escapeHtml(u.input)}
            </div>
            <div class="verdict-tag status-${u.verdict}" style="font-size: 0.8rem; padding: 2px 10px; margin: 0;">
              ${escapeHtml(u.verdict)} (${u.score}/100)
            </div>
          </div>
        `).join('')}
      </div>
    </div>
  ` : `<p style="color: var(--color-text-muted); font-size: 0.9rem; margin-bottom: var(--space-4);">No web URLs found in the text.</p>`;

  const triggerSection = matchedTriggers.length > 0 ? `
    <div style="margin-bottom: var(--space-6);">
      <h4 style="font-size: 1rem; font-weight: 600; margin-bottom: var(--space-3);">
        Social Engineering & Urgency Phrases Detected (${matchedTriggers.length})
      </h4>
      <div style="display: flex; flex-wrap: wrap; gap: var(--space-2);">
        ${matchedTriggers.map(t => `
          <span style="background-color: var(--color-phishing-bg); border: 1px solid var(--color-phishing-border); color: var(--color-phishing); font-size: 0.8rem; padding: 4px 10px; border-radius: var(--radius-full); font-weight: 500;">
            "${escapeHtml(t.keyword)}" (${escapeHtml(t.category)})
          </span>
        `).join('')}
      </div>
    </div>
  ` : '';

  const mismatchSection = htmlMismatches.length > 0 ? `
    <div class="card" style="border-left: 4px solid var(--color-phishing); margin-bottom: var(--space-6);">
      <h4 style="font-size: 1rem; font-weight: 600; color: var(--color-phishing); margin-bottom: var(--space-2);">
        CRITICAL: Hyperlink Text vs Destination Mismatch
      </h4>
      ${htmlMismatches.map(m => `
        <p style="font-size: 0.88rem; color: var(--color-text-primary); margin-bottom: 6px;">
          Visible Anchor: <code>${escapeHtml(m.visibleText)}</code> ➔ Real Destination: <code>${escapeHtml(m.actualHref)}</code>
        </p>
      `).join('')}
    </div>
  ` : '';

  return `
    <div class="card">
      ${mismatchSection}
      ${urlSection}
      ${triggerSection}
    </div>
  `;
}

/**
 * Renders the scan history table.
 * @param {object[]} history 
 * @returns {string} HTML string
 */
export function renderHistoryTable(history) {
  if (!history || history.length === 0) {
    return `
      <div class="empty-state">
        <div class="empty-icon">${ICONS.link}</div>
        <p>No scans recorded yet in local session storage.</p>
      </div>
    `;
  }

  const rowsHtml = history.map((h, i) => `
    <tr>
      <td>${new Date(h.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}</td>
      <td style="font-family: var(--font-mono); font-size: 0.85rem; max-width: 320px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
        ${escapeHtml(h.input)}
      </td>
      <td>
        <span class="verdict-tag status-${h.verdict}" style="font-size: 0.75rem; padding: 2px 8px; margin: 0;">
          ${escapeHtml(h.verdict)} (${h.score})
        </span>
      </td>
      <td>
        <button class="chip-btn" onclick="window.replayScan(${i})">Re-analyze</button>
      </td>
    </tr>
  `).join('');

  return `
    <table class="history-table">
      <thead>
        <tr>
          <th>Time</th>
          <th>Input</th>
          <th>Verdict</th>
          <th>Action</th>
        </tr>
      </thead>
      <tbody>
        ${rowsHtml}
      </tbody>
    </table>
  `;
}
