import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { parseUrl } from '../../src/engine/parser.js';
import { brandImpersonationRule } from '../../src/engine/rules/brand-impersonation.js';

describe('Rule: brand-impersonation', () => {
  test('flags brand name in subdomain of unaffiliated domain', () => {
    const parsed = parseUrl('http://paypal.com.secure-login.xyz/verify');
    const res = brandImpersonationRule.check(parsed);
    assert.equal(res.triggered, true);
    assert.equal(res.brandMatched, 'PayPal');
    assert.equal(res.riskySegment, 'subdomain');
  });

  test('flags brand name in compound domain', () => {
    const parsed = parseUrl('https://chase-security-update.com/login');
    const res = brandImpersonationRule.check(parsed);
    assert.equal(res.triggered, true);
    assert.equal(res.brandMatched, 'Chase Bank');
  });

  test('does not flag authentic brand domain (paypal.com)', () => {
    const parsed = parseUrl('https://www.paypal.com/signin');
    const res = brandImpersonationRule.check(parsed);
    assert.equal(res.triggered, false);
  });

  test('does not flag authentic Google subdomain (accounts.google.com)', () => {
    const parsed = parseUrl('https://accounts.google.com/signin');
    const res = brandImpersonationRule.check(parsed);
    assert.equal(res.triggered, false);
  });

  test('does not flag regional Amazon domain (www.amazon.in)', () => {
    const parsed = parseUrl('https://www.amazon.in/dp/12345');
    const res = brandImpersonationRule.check(parsed);
    assert.equal(res.triggered, false);
  });
});
