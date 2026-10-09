import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { parseUrl } from '../../src/engine/parser.js';
import { insecureSchemeRule } from '../../src/engine/rules/insecure-scheme.js';

describe('Rule: insecure-scheme', () => {
  test('flags explicit plain HTTP scheme', () => {
    const parsed = parseUrl('http://example.com');
    const res = insecureSchemeRule.check(parsed);
    assert.equal(res.triggered, true);
    assert.match(res.evidence, /unencrypted HTTP/i);
  });

  test('flags javascript: pseudo-protocol with critical severity', () => {
    const parsed = parseUrl('javascript:alert(1)');
    const res = insecureSchemeRule.check(parsed);
    assert.equal(res.triggered, true);
    assert.equal(res.severityOverride, 'critical');
  });

  test('flags data: URI scheme with high severity', () => {
    const parsed = parseUrl('data:text/html;base64,PHNjcmlwdD4=');
    const res = insecureSchemeRule.check(parsed);
    assert.equal(res.triggered, true);
    assert.equal(res.severityOverride, 'high');
  });

  test('does not flag standard HTTPS scheme', () => {
    const parsed = parseUrl('https://example.com');
    const res = insecureSchemeRule.check(parsed);
    assert.equal(res.triggered, false);
  });
});
