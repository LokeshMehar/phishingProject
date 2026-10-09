import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { parseUrl } from '../../src/engine/parser.js';
import { userinfoRule } from '../../src/engine/rules/userinfo.js';

describe('Rule: userinfo', () => {
  test('flags deceptive userinfo @ trick', () => {
    const parsed = parseUrl('https://paypal.com@evil-site.com/signin');
    const res = userinfoRule.check(parsed);
    assert.equal(res.triggered, true);
    assert.equal(res.riskySegment, 'userInfo');
    assert.match(res.evidence, /userinfo/i);
  });

  test('flags user:pass@host pattern', () => {
    const parsed = parseUrl('https://google.com:secret@attacker.xyz');
    const res = userinfoRule.check(parsed);
    assert.equal(res.triggered, true);
  });

  test('does not flag normal URLs without @', () => {
    const parsed = parseUrl('https://paypal.com/signin');
    const res = userinfoRule.check(parsed);
    assert.equal(res.triggered, false);
  });
});
