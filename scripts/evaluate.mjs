/**
 * PhishGuard Corpus Evaluation Script
 * 
 * Runs the deterministic detection engine across the curated test corpus
 * (legitimate and phishing fixtures) using zero external dependencies.
 * Computes confusion matrix, precision, recall, and F1 score.
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { analyze } from '../src/engine/index.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const legitPath = join(__dirname, '../tests/fixtures/legitimate.json');
const phishPath = join(__dirname, '../tests/fixtures/phishing.json');

const legitSamples = JSON.parse(readFileSync(legitPath, 'utf-8'));
const phishSamples = JSON.parse(readFileSync(phishPath, 'utf-8'));

console.log('='.repeat(65));
console.log('         PHISHGUARD DETECTION ENGINE BENCHMARK EVALUATION        ');
console.log('='.repeat(65));
console.log(`Evaluating ${legitSamples.length} legitimate and ${phishSamples.length} phishing fixtures...\n`);

let tp = 0; // Phishing correctly flagged as Phishing or Suspicious
let fn = 0; // Phishing missed (labeled Safe)
let tn = 0; // Legitimate correctly labeled Safe
let fp = 0; // Legitimate incorrectly flagged as Phishing or Suspicious

const misclassified = [];

// Evaluate legitimate samples
for (const sample of legitSamples) {
  const result = analyze(sample.url);
  // Legitimate sample is considered correctly classified if Safe
  if (result.verdict === 'Safe') {
    tn++;
  } else {
    fp++;
    misclassified.push({
      url: sample.url,
      type: 'Legitimate',
      actualVerdict: result.verdict,
      score: result.score,
      evidence: result.evidence.map(e => e.id)
    });
  }
}

// Evaluate phishing samples
for (const sample of phishSamples) {
  const result = analyze(sample.url);
  // Phishing is considered correctly detected if flagged as Phishing or Suspicious
  if (result.verdict === 'Phishing' || result.verdict === 'Suspicious') {
    tp++;
  } else {
    fn++;
    misclassified.push({
      url: sample.url,
      type: 'Phishing',
      actualVerdict: result.verdict,
      score: result.score,
      evidence: result.evidence.map(e => e.id)
    });
  }
}

const total = legitSamples.length + phishSamples.length;
const accuracy = ((tp + tn) / total) * 100;
const precision = (tp / (tp + fp)) * 100;
const recall = (tp / (tp + fn)) * 100;
const f1 = (2 * (precision * recall) / (precision + recall));

console.log('--- CONFUSION MATRIX ---');
console.log(`                 Actual Phishing    Actual Legitimate`);
console.log(`Flagged Threat:  TP = ${String(tp).padEnd(16)} FP = ${String(fp).padEnd(16)}`);
console.log(`Marked Safe:     FN = ${String(fn).padEnd(16)} TN = ${String(tn).padEnd(16)}`);
console.log('\n--- PERFORMANCE METRICS ---');
console.log(`Total Samples:      ${total}`);
console.log(`Accuracy:           ${accuracy.toFixed(2)}%`);
console.log(`Precision:          ${precision.toFixed(2)}%`);
console.log(`Recall:             ${recall.toFixed(2)}%`);
console.log(`F1 Score:           ${(f1 / 100).toFixed(4)}`);
console.log('='.repeat(65));

if (misclassified.length > 0) {
  console.log(`\nMisclassified Samples (${misclassified.length}):`);
  for (const m of misclassified) {
    console.log(`- [${m.type}] ${m.url} -> Verdict: ${m.actualVerdict} (Score: ${m.score}) Triggered: ${m.evidence.join(', ')}`);
  }
} else {
  console.log('\nAll corpus samples classified exactly as expected (0 misclassifications).');
}

export { tp, fp, tn, fn, accuracy, precision, recall, f1, misclassified };
