# Contributing

Thanks for helping improve jwt-oauth-cli.

## Setup

- Node.js 20 or newer
- npm install

## Checks

- npm run lint — syntax check of src/
- npm test — node:test suite under test/

## Guidelines

- Keep the CLI ESM-only ("type": "module").
- Prefer jose for JWT work; do not add signature verification unless explicitly scoped and covered by tests.
- OAuth helpers should stay local-first: no hardcoded IdP hostnames, avoid logging client credentials or tokens.
- Add or update tests for new commands and URL/body construction.
- Keep commits focused; open PRs against main.

## Security

Do not commit credentials or real production tokens. Use placeholders in examples and fixtures.
