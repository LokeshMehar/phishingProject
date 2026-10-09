# How to Add a New Detection Rule to PhishGuard

PhishGuard's detection pipeline is fully modular. Adding a new heuristic rule does not require modifying the scoring algorithm or UI rendering logic. Follow this guide to implement and register a rule.

---

## Step 1: Create the Rule Module

Create a new file in `src/engine/rules/<rule-name>.js`.

Every rule must conform to the following interface:

```javascript
import { ENGINE_CONFIG } from '../config.js';

export const myCustomRule = {
  // Unique machine identifier
  id: 'my-custom-rule',

  // Human-readable title displayed in evidence reports
  title: 'Descriptive Rule Title',

  // Severity category: 'critical' | 'high' | 'medium' | 'low' | 'info'
  severity: ENGINE_CONFIG.severities.MEDIUM,

  // Base score weight (defined in config.js)
  weight: ENGINE_CONFIG.weights['my-custom-rule'] || 20,

  /**
   * Inspection function evaluated against parsed URL object.
   * Must be side-effect free and deterministic.
   * 
   * @param {object} parsedUrl 
   * @returns {{ triggered: boolean, evidence?: string, riskySegment?: string }}
   */
  check(parsedUrl) {
    if (!parsedUrl || !parsedUrl.valid) {
      return { triggered: false };
    }

    // Example logic
    if (parsedUrl.pathname.includes('/evil-endpoint')) {
      return {
        triggered: true,
        evidence: "URL path targets suspicious endpoint '/evil-endpoint'",
        riskySegment: 'pathname' // 'scheme' | 'userInfo' | 'subdomain' | 'registrableDomain' | 'port' | 'pathname'
      };
    }

    return { triggered: false };
  },

  explanation: 'Explain in plain English why this pattern presents cybersecurity risk.',
  advice: 'Explain what the end user should do when encountering this indicator.'
};
```

---

## Step 2: Register in Rule Registry

Open `src/engine/rules/index.js` and add your rule:

```javascript
import { myCustomRule } from './my-custom-rule.js';

export const ALL_RULES = [
  // ... existing rules
  myCustomRule
];
```

---

## Step 3: Configure Weights and Combinations

Open `src/engine/config.js` to set the weight and any combination bonuses:

```javascript
weights: {
  // ...
  'my-custom-rule': 20
}
```

---

## Step 4: Write Unit Tests

Create `tests/rules/my-custom-rule.test.js`:

```javascript
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { parseUrl } from '../../src/engine/parser.js';
import { myCustomRule } from '../../src/engine/rules/my-custom-rule.js';

describe('Rule: my-custom-rule', () => {
  test('flags malicious pattern', () => {
    const parsed = parseUrl('https://example.com/evil-endpoint');
    const res = myCustomRule.check(parsed);
    assert.equal(res.triggered, true);
    assert.match(res.evidence, /evil-endpoint/);
  });

  test('does not flag benign input', () => {
    const parsed = parseUrl('https://example.com/safe-endpoint');
    const res = myCustomRule.check(parsed);
    assert.equal(res.triggered, false);
  });
});
```

---

## Step 5: Validate with the Corpus

Run tests and benchmark:

```bash
# Run all tests
node --test

# Run benchmark evaluation
node scripts/evaluate.mjs
```
Ensure your new rule introduces 0 false positives on `tests/fixtures/legitimate.json`.
