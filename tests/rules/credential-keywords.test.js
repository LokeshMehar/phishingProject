import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { parseUrl } from '../../src/engine/parser.js';
import { credentialKeywordsRule } from '../../src/engine/rules/credential-keywords.js';

describe('Rule: credential-keywords', () => {
  test('flags credential keywords in path', () => {
    const parsed = parseUrl('https://example-test.com/login/verify.php');
    const res = credentialKeywordsRule.check(parsed);
    assert.equal(res.triggered, true);
    assert.match(res.evidence, /credential-related keywords/i);
  });

  test('flags authentication keywords in host', () => {
    const parsed = parseUrl('https://secure-banking-portal.net');
    const res = credentialKeywordsRule.check(parsed);
    assert.equal(res.triggered, true);
  });

  test('does not flag URLs without security/auth keywords', () => {
    const parsed = parseUrl('https://example.com/about/contact-us');
    const res = credentialKeywordsRule.check(parsed);
    assert.equal(res.triggered, false);
  });
});
