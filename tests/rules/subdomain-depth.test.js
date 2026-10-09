import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { parseUrl } from '../../src/engine/parser.js';
import { subdomainDepthRule } from '../../src/engine/rules/subdomain-depth.js';

describe('Rule: subdomain-depth', () => {
  test('flags deep subdomains (>3 levels)', () => {
    const parsed = parseUrl('http://a.b.c.d.example.com');
    const res = subdomainDepthRule.check(parsed);
    assert.equal(res.triggered, true);
    assert.match(res.evidence, /subdomain levels/i);
  });

  test('flags excessive hyphens in hostname', () => {
    const parsed = parseUrl('http://secure-login-verify-account-update.com');
    const res = subdomainDepthRule.check(parsed);
    assert.equal(res.triggered, true);
    assert.match(res.evidence, /hyphens/i);
  });

  test('does not flag standard 1-2 level subdomains', () => {
    const parsed = parseUrl('https://accounts.google.com');
    const res = subdomainDepthRule.check(parsed);
    assert.equal(res.triggered, false);
  });
});
