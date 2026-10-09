import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { parseUrl } from '../../src/engine/parser.js';
import { typosquattingRule, damerauLevenshtein } from '../../src/engine/rules/typosquatting.js';

describe('Rule: typosquatting', () => {
  test('computes Damerau-Levenshtein distance correctly', () => {
    assert.equal(damerauLevenshtein('google', 'goolge'), 1); // transposition
    assert.equal(damerauLevenshtein('paypal', 'paypa1'), 1); // substitution
    assert.equal(damerauLevenshtein('apple', 'aple'), 1);    // deletion
    assert.equal(damerauLevenshtein('netflix', 'netflx'), 1);
  });

  test('flags typosquatted domain paypa1.com', () => {
    const parsed = parseUrl('http://paypa1.com/login');
    const res = typosquattingRule.check(parsed);
    assert.equal(res.triggered, true);
    assert.equal(res.targetBrand, 'PayPal');
  });

  test('flags goolge.com', () => {
    const parsed = parseUrl('http://goolge.com/signin');
    const res = typosquattingRule.check(parsed);
    assert.equal(res.triggered, true);
    assert.equal(res.targetBrand, 'Google');
  });

  test('does not flag authentic domain (google.com)', () => {
    const parsed = parseUrl('https://google.com');
    const res = typosquattingRule.check(parsed);
    assert.equal(res.triggered, false);
  });

  test('does not trigger on very short unrelated domains', () => {
    const parsed = parseUrl('https://cat.org');
    const res = typosquattingRule.check(parsed);
    assert.equal(res.triggered, false);
  });
});
