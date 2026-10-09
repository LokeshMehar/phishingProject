import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { parseUrl } from '../../src/engine/parser.js';
import { homographIdnRule, normalizeConfusables } from '../../src/engine/rules/homograph-idn.js';

describe('Rule: homograph-idn', () => {
  test('flags Punycode (xn--) hostnames', () => {
    const parsed = parseUrl('http://xn--pple-43d.com/login');
    const res = homographIdnRule.check(parsed);
    assert.equal(res.triggered, true);
    assert.match(res.evidence, /Punycode/i);
  });

  test('normalizes visual confusables (rn -> m, 0 -> o)', () => {
    assert.equal(normalizeConfusables('arnazon'), 'amazon');
    assert.equal(normalizeConfusables('micros0ft'), 'microsoft');
  });

  test('flags leetspeak and visual digraph confusables', () => {
    const parsed = parseUrl('http://micros0ft.com/account');
    const res = homographIdnRule.check(parsed);
    assert.equal(res.triggered, true);
  });

  test('does not flag normal ascii domain', () => {
    const parsed = parseUrl('https://apple.com');
    const res = homographIdnRule.check(parsed);
    assert.equal(res.triggered, false);
  });
});
