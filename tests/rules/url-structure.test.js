import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { parseUrl } from '../../src/engine/parser.js';
import { urlStructureRule } from '../../src/engine/rules/url-structure.js';

describe('Rule: url-structure', () => {
  test('flags non-standard network port on external domain', () => {
    const parsed = parseUrl('http://example-phish.xyz:2082/login');
    const res = urlStructureRule.check(parsed);
    assert.equal(res.triggered, true);
    assert.match(res.evidence, /non-standard network port/i);
  });

  test('does not flag standard port 80 or 443', () => {
    const parsed = parseUrl('https://example.com:443/test');
    const res = urlStructureRule.check(parsed);
    assert.equal(res.triggered, false);
  });

  test('flags double-slash path redirect sequences', () => {
    const parsed = parseUrl('http://example.com//evil.com/redirect');
    const res = urlStructureRule.check(parsed);
    assert.equal(res.triggered, true);
    assert.match(res.evidence, /double forward-slash/i);
  });

  test('flags excessive percent-encoded characters', () => {
    const parsed = parseUrl('http://example.com/%2e%2e/%2f%2e%2e/test');
    const res = urlStructureRule.check(parsed);
    assert.equal(res.triggered, true);
    assert.match(res.evidence, /percent-encoded/i);
  });
});
