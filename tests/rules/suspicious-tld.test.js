import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { parseUrl } from '../../src/engine/parser.js';
import { suspiciousTldRule } from '../../src/engine/rules/suspicious-tld.js';

describe('Rule: suspicious-tld', () => {
  test('flags .xyz TLD as weak signal', () => {
    const parsed = parseUrl('http://my-test-portal.xyz');
    const res = suspiciousTldRule.check(parsed);
    assert.equal(res.triggered, true);
    assert.equal(suspiciousTldRule.severity, 'low');
    assert.match(res.evidence, /\.xyz/);
  });

  test('flags .top TLD', () => {
    const parsed = parseUrl('http://update-system.top');
    const res = suspiciousTldRule.check(parsed);
    assert.equal(res.triggered, true);
  });

  test('does not flag standard .com TLD', () => {
    const parsed = parseUrl('https://example.com');
    const res = suspiciousTldRule.check(parsed);
    assert.equal(res.triggered, false);
  });

  test('does not flag .gov or .edu TLD', () => {
    const parsed = parseUrl('https://mit.edu');
    const res = suspiciousTldRule.check(parsed);
    assert.equal(res.triggered, false);
  });
});
