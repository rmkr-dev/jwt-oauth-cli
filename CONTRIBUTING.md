# Contributing

Thanks for helping improve jwt-oauth-cli.

## Setup

- JDK 17 or newer
- Apache Maven 3.9+

```bash
mvn test
```

## Checks

- `mvn -q test` — JUnit 5 suite under `src/test/java`
- `mvn -q package` — shaded runnable jar

## Guidelines

- Keep the CLI on Picocli with `jwt` and `oauth` command groups.
- Prefer Nimbus JOSE+JWT for JWT work; do not add signature verification unless
  explicitly scoped and covered by tests.
- OAuth helpers should stay local-first: no hardcoded IdP hostnames, avoid
  logging client credentials or tokens.
- Inject `FormPoster` (or equivalent) in library methods so token POST bodies
  can be unit-tested without a live IdP.
- Add or update tests for new commands and URL/body construction.
- Keep commits focused; open PRs against `main`.

## Security

Do not commit credentials or real production tokens. Use placeholders in
examples and fixtures.
