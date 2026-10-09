import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { analyze } from '../src/engine/index.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const legitSamples = JSON.parse(readFileSync(join(__dirname, 'fixtures/legitimate.json'), 'utf-8'));
const phishSamples = JSON.parse(readFileSync(join(__dirname, 'fixtures/phishing.json'), 'utf-8'));

describe('Corpus Validation Test Suite', () => {
  describe('Legitimate Fixtures (Zero False Positives Target)', () => {
    for (const sample of legitSamples) {
      test(`verifies authentic URL: ${sample.url}`, () => {
        const result = analyze(sample.url);
        assert.equal(
          result.verdict,
          'Safe',
          `Expected Safe for ${sample.url}, got ${result.verdict} (Score: ${result.score}, Rules: ${result.evidence.map(e => e.id).join(', ')})`
        );
      });
    }
  });

  describe('Phishing Fixtures (Zero False Negatives Target)', () => {
    for (const sample of phishSamples) {
      test(`detects phishing threat: ${sample.url}`, () => {
        const result = analyze(sample.url);
        assert.ok(
          result.verdict === 'Phishing' || result.verdict === 'Suspicious',
          `Expected Phishing or Suspicious for ${sample.url}, got ${result.verdict} (Score: ${result.score})`
        );
      });
    }
  });
});
