import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { parseUrl } from '../../src/engine/parser.js';
import { urlShortenerRule } from '../../src/engine/rules/url-shortener.js';

describe('Rule: url-shortener', () => {
  test('flags bit.ly shortener', () => {
    const parsed = parseUrl('https://bit.ly/3xYzA1');
    const res = urlShortenerRule.check(parsed);
    assert.equal(res.triggered, true);
    assert.match(res.evidence, /URL shortening service/i);
  });

  test('flags tinyurl.com', () => {
    const parsed = parseUrl('https://tinyurl.com/xyz123');
    const res = urlShortenerRule.check(parsed);
    assert.equal(res.triggered, true);
  });

  test('does not flag full domains', () => {
    const parsed = parseUrl('https://github.com/torvalds/linux');
    const res = urlShortenerRule.check(parsed);
    assert.equal(res.triggered, false);
  });
});
