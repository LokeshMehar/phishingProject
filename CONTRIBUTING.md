# Contributing to PhishGuard

We welcome contributions to PhishGuard! This project is maintained as a transparent, deterministic phishing defense system built with zero runtime dependencies.

## Development Principles

1. **Zero Runtime Dependencies**: The core engine must run in any modern web browser or standard Node 20+ runtime without external libraries.
2. **Deterministic & Explainable**: Every detection must map to clear evidence, severity, explanation, and user advice. No black-box verdicts.
3. **High Precision**: False positives on legitimate websites (like `accounts.google.com` or `amazon.co.uk`) are treated with the highest severity. All new rules must be tested against legitimate and malicious fixtures.
4. **Side-Effect Free**: The analysis engine takes a string and returns structured JSON. It never executes shell commands or makes unprompted network calls.

## How to Add a Detection Rule

To add a new detection rule, follow our guide at [`docs/adding-a-rule.md`](docs/adding-a-rule.md):
1. Create `src/engine/rules/<rule-id>.js`.
2. Implement `{ id, title, severity, weight, check(parsedUrl), explanation, advice }`.
3. Register the rule in `src/engine/rules/index.js`.
4. Configure weights in `src/engine/config.js`.
5. Add unit tests in `tests/rules/<rule-id>.test.js`.
6. Add test cases to `tests/fixtures/legitimate.json` and `tests/fixtures/phishing.json`.
7. Verify all tests pass with `npm test` and run `npm run evaluate`.

## Submitting Pull Requests

- Ensure all tests pass: `node --test`
- Run evaluation: `node scripts/evaluate.mjs`
- Keep code clean and self-documenting with JSDoc comments.
