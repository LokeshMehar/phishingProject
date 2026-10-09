/**
 * PhishGuard Main Application Controller
 * 
 * Coordinates UI state, event handling, theme toggling,
 * analysis dispatching, and persistent session history.
 */

import { analyze } from '../engine/index.js';
import {
  renderRiskGauge,
  renderUrlSegments,
  renderEvidenceList,
  renderTextAnalysis,
  renderHistoryTable
} from './render.js';
import { ICONS, escapeHtml } from './dom.js';

// State
let currentTab = 'url';
let currentResult = null;
let scanHistory = [];

const STORAGE_KEY_THEME = 'phishguard-theme';
const STORAGE_KEY_HISTORY = 'phishguard-history';

// DOM Elements
const urlInput = document.getElementById('urlInput');
const textInput = document.getElementById('textInput');
const resultsArea = document.getElementById('resultsArea');
const ariaLive = document.getElementById('ariaLiveRegion');
const themeToggleBtn = document.getElementById('themeToggleBtn');
const statTotal = document.getElementById('statTotal');
const statThreats = document.getElementById('statThreats');
const statSafe = document.getElementById('statSafe');

/**
 * Initializes application state and event bindings.
 */
export function init() {
  loadTheme();
  loadHistory();
  updateStats();
  setupEventListeners();

  // Expose replayScan globally for inline onclick in history table
  window.replayScan = (index) => {
    const item = scanHistory[index];
    if (!item) return;

    if (item.type === 'text') {
      switchTab('text');
      if (textInput) textInput.value = item.input;
      runAnalysis(item.input);
    } else {
      switchTab('url');
      if (urlInput) urlInput.value = item.input;
      runAnalysis(item.input);
    }
  };
}

/**
 * Sets up user interaction listeners.
 */
function setupEventListeners() {
  // Theme toggle
  if (themeToggleBtn) {
    themeToggleBtn.addEventListener('click', toggleTheme);
  }

  // Navigation tabs
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const tab = e.currentTarget.dataset.tab;
      if (tab) switchTab(tab);
    });
  });

  // URL Run Button
  const analyzeUrlBtn = document.getElementById('analyzeUrlBtn');
  if (analyzeUrlBtn) {
    analyzeUrlBtn.addEventListener('click', () => {
      const val = urlInput?.value.trim();
      if (val) runAnalysis(val);
    });
  }

  // URL Input Enter key
  if (urlInput) {
    urlInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        const val = urlInput.value.trim();
        if (val) runAnalysis(val);
      }
    });
  }

  // Text Run Button
  const analyzeTextBtn = document.getElementById('analyzeTextBtn');
  if (analyzeTextBtn) {
    analyzeTextBtn.addEventListener('click', () => {
      const val = textInput?.value.trim();
      if (val) runAnalysis(val);
    });
  }

  // Clear Buttons
  document.getElementById('clearUrlBtn')?.addEventListener('click', () => {
    if (urlInput) {
      urlInput.value = '';
      urlInput.focus();
    }
    clearResults();
  });

  document.getElementById('clearTextBtn')?.addEventListener('click', () => {
    if (textInput) {
      textInput.value = '';
      textInput.focus();
    }
    clearResults();
  });

  // Example Chips
  document.querySelectorAll('.chip-btn[data-sample]').forEach(chip => {
    chip.addEventListener('click', (e) => {
      const sample = e.currentTarget.dataset.sample;
      if (currentTab === 'text') {
        if (textInput) textInput.value = sample;
      } else {
        if (urlInput) urlInput.value = sample;
      }
      runAnalysis(sample);
    });
  });

  // Clear History
  document.getElementById('clearHistoryBtn')?.addEventListener('click', () => {
    scanHistory = [];
    localStorage.removeItem(STORAGE_KEY_HISTORY);
    updateStats();
    renderActiveTab();
  });
}

/**
 * Runs analysis and updates UI.
 * @param {string} input 
 */
export function runAnalysis(input) {
  if (!input) return;

  const result = analyze(input);
  currentResult = result;

  // Persist to session history
  saveToHistory({
    input,
    type: result.type,
    verdict: result.verdict,
    score: result.score,
    timestamp: Date.now()
  });

  // Render Result in UI
  renderAnalysisResult(result);

  // Announce to Screen Readers via ARIA Live Region
  if (ariaLive) {
    ariaLive.textContent = `Analysis complete: Verdict is ${result.verdict} with risk score ${result.score} out of 100. ${result.summary}`;
  }
}

/**
 * Renders the analysis result into resultsArea.
 * @param {object} result 
 */
function renderAnalysisResult(result) {
  if (!resultsArea) return;

  if (!result.valid) {
    resultsArea.innerHTML = `
      <div class="card" style="border-left: 4px solid var(--color-suspicious); padding: var(--space-6);">
        <h3 style="font-size: 1.1rem; color: var(--color-suspicious); margin-bottom: var(--space-2);">Invalid Input Format</h3>
        <p style="color: var(--color-text-secondary);">${escapeHtml(result.error || 'Please enter a valid URL or text snippet.')}</p>
      </div>
    `;
    return;
  }

  let html = `
    <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: var(--space-4); flex-wrap: wrap; gap: var(--space-2);">
      <div>
        <h2 style="font-size: 1.3rem; font-weight: 700; letter-spacing: -0.02em;">Forensic Security Report</h2>
        <p style="font-size: 0.88rem; color: var(--color-text-secondary);">${escapeHtml(result.summary)}</p>
      </div>
      <button class="btn btn-secondary" id="copyReportBtn" style="font-size: 0.82rem; padding: 0.4rem 0.9rem;">
        ${ICONS.copy}
        <span id="copyBtnText">Copy Report</span>
      </button>
    </div>
  `;

  // If URL type, render URL Segment Decomposition
  if (result.type === 'url' && result.urlSegments) {
    html += renderUrlSegments(result.urlSegments, result.primaryRiskSegment, result.verdict);
  }

  // Render Grid: Gauge + Evidence
  html += `
    <div class="results-grid">
      ${renderRiskGauge(result.score, result.verdict)}
      ${result.type === 'url'
        ? renderEvidenceList(result.evidence, result.combinationBonuses, result.dampenedRules)
        : renderTextAnalysis(result)}
    </div>
  `;

  resultsArea.innerHTML = html;

  // Bind copy button
  document.getElementById('copyReportBtn')?.addEventListener('click', copyReport);
}

/**
 * Copies plain-text report summary to clipboard.
 */
function copyReport() {
  if (!currentResult) return;
  const reportText = `[PhishGuard Security Report]
Target: ${currentResult.input}
Verdict: ${currentResult.verdict} (Risk Score: ${currentResult.score}/100)
Summary: ${currentResult.summary}
Indicators: ${currentResult.evidence?.map(e => `[${e.severity.toUpperCase()}] ${e.title}: ${e.evidence}`).join('\n') || 'None'}`;

  navigator.clipboard.writeText(reportText).then(() => {
    const copyBtnText = document.getElementById('copyBtnText');
    if (copyBtnText) {
      copyBtnText.textContent = 'Copied!';
      setTimeout(() => { copyBtnText.textContent = 'Copy Report'; }, 2000);
    }
  });
}

function clearResults() {
  if (resultsArea) {
    resultsArea.innerHTML = `
      <div class="empty-state">
        <div class="empty-icon">${ICONS.shield}</div>
        <p>Enter a web URL or paste a suspicious message to begin forensic inspection.</p>
      </div>
    `;
  }
}

/**
 * Tab switching controller.
 * @param {string} tab 
 */
function switchTab(tab) {
  currentTab = tab;
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.tab === tab);
  });

  const urlSection = document.getElementById('urlSection');
  const textSection = document.getElementById('textSection');
  const historySection = document.getElementById('historySection');

  if (urlSection) urlSection.style.display = tab === 'url' ? 'block' : 'none';
  if (textSection) textSection.style.display = tab === 'text' ? 'block' : 'none';
  if (historySection) historySection.style.display = tab === 'history' ? 'block' : 'none';

  if (tab === 'history') {
    renderHistoryView();
  }
}

function renderHistoryView() {
  const container = document.getElementById('historyTableContainer');
  if (container) {
    container.innerHTML = renderHistoryTable(scanHistory);
  }
}

function renderActiveTab() {
  if (currentTab === 'history') {
    renderHistoryView();
  }
}

/**
 * History storage management.
 */
function saveToHistory(record) {
  scanHistory.unshift(record);
  if (scanHistory.length > 50) {
    scanHistory.pop();
  }
  try {
    localStorage.setItem(STORAGE_KEY_HISTORY, JSON.stringify(scanHistory));
  } catch {
    // quota exceeded / private mode
  }
  updateStats();
}

function loadHistory() {
  try {
    const saved = localStorage.getItem(STORAGE_KEY_HISTORY);
    if (saved) {
      scanHistory = JSON.parse(saved);
    }
  } catch {
    scanHistory = [];
  }
}

function updateStats() {
  const total = scanHistory.length;
  const threats = scanHistory.filter(h => h.verdict === 'Phishing' || h.verdict === 'Suspicious').length;
  const safe = scanHistory.filter(h => h.verdict === 'Safe').length;

  if (statTotal) statTotal.textContent = total;
  if (statThreats) statThreats.textContent = threats;
  if (statSafe) statSafe.textContent = safe;
}

/**
 * Theme management.
 */
function toggleTheme() {
  const current = document.documentElement.getAttribute('data-theme') || 'dark';
  const next = current === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', next);
  try {
    localStorage.setItem(STORAGE_KEY_THEME, next);
  } catch {}
  updateThemeIcon(next);
}

function loadTheme() {
  let theme = 'dark';
  try {
    theme = localStorage.getItem(STORAGE_KEY_THEME) || 'dark';
  } catch {}
  document.documentElement.setAttribute('data-theme', theme);
  updateThemeIcon(theme);
}

function updateThemeIcon(theme) {
  const iconSpan = document.getElementById('themeIcon');
  if (iconSpan) {
    iconSpan.innerHTML = theme === 'dark' ? ICONS.sun : ICONS.moon;
  }
  const textSpan = document.getElementById('themeText');
  if (textSpan) {
    textSpan.textContent = theme === 'dark' ? 'Light Mode' : 'Dark Mode';
  }
}

// Auto-run on DOMContentLoaded
if (typeof document !== 'undefined') {
  document.addEventListener('DOMContentLoaded', init);
}
