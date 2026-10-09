import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { parseUrl } from '../../src/engine/parser.js';
import { ipHostRule } from '../../src/engine/rules/ip-host.js';

describe('Rule: ip-host', () => {
  test('flags dotted decimal IPv4 host', () => {
    const parsed = parseUrl('http://192.168.1.1/login');
    const res = ipHostRule.check(parsed);
    assert.equal(res.triggered, true);
    assert.match(res.evidence, /raw IP address/i);
  });

  test('flags hexadecimal IPv4 host', () => {
    const parsed = parseUrl('http://0x7f000001/verify');
    const res = ipHostRule.check(parsed);
    assert.equal(res.triggered, true);
  });

  test('flags octal IPv4 host', () => {
    const parsed = parseUrl('http://017700000001/auth');
    const res = ipHostRule.check(parsed);
    assert.equal(res.triggered, true);
  });

  test('flags 32-bit integer IPv4 host', () => {
    const parsed = parseUrl('http://2130706433/login');
    const res = ipHostRule.check(parsed);
    assert.equal(res.triggered, true);
  });

  test('does not flag standard registered domain', () => {
    const parsed = parseUrl('https://accounts.google.com');
    const res = ipHostRule.check(parsed);
    assert.equal(res.triggered, false);
  });
});
