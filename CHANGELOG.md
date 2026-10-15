# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/). Dates are when the release was
merged to `main`.

## [Unreleased]

## [1.0.0] - 2026-10-15

The authorization code flow can now be tested end to end from a terminal:
`oauth pkce` → `oauth authorize-url` → `oauth callback` → `oauth exchange`.

### Added

- `oauth callback`: one-shot loopback HTTP listener for the authorization
  redirect. Serves the host, port, and path from `--redirect-uri`, prints
  `code` and `state` (plus `iss`, `scope`, `session_state` when present) as
  JSON and exits 0, or prints `error`, `error_description`, `error_uri`, and
  `state` and exits 1 on an error redirect.
- `--expected-state` rejects a missing or different `state` without
  returning the code; `--timeout-seconds` (default 300), `--bind`,
  `--success-html`, `--error-html`, and `-c/--compact`.
- Requests to other paths (404), without `code` or `error` (400), or with a
  method other than GET (405) do not end the wait; the listener gives up after
  50 of them.
- `oauth.CallbackSupport` library helpers: `parseRedirectUri`, `parseQuery`,
  `evaluate`, `successHtml`, `errorHtml`, and `await(Options)`.
- This changelog.

## [0.9.0] - 2026-10-13

### Added

- JWT client authentication for token-endpoint calls (RFC 7523, OIDC Core
  section 9): `--client-auth private_key_jwt` with `--client-jwk-file`, and
  `--client-auth client_secret_jwt`, plus `basic` and `post`. Shared by
  `exchange`, `refresh`, `client-credentials`, `device-code`, `device-token`,
  `introspect`, and `revoke`, with `--assertion-alg`, `--assertion-aud`, and
  `--assertion-lifetime`.
- `oauth client-assertion` to print a client assertion without calling any
  endpoint.

### Fixed

- `--version` reported 0.5.0.

## [0.8.0] - 2026-10-11

### Added

- `jwt sign --jwk-file` signs with a private RSA or EC JWK (RS*, PS*, ES*).
- `jwt verify --jwks-file` verifies against a local JWKS or public JWK with no
  network call.

### Fixed

- ES algorithm is inferred from the EC curve name.

## [0.7.0] - 2026-10-09

### Added

- `jwt keygen` for RSA, EC, and HMAC JWKs, with public JWK and JWKS output for
  asymmetric keys.

## [0.6.0] - 2026-09-29

### Added

- `oauth discover` for OpenID Provider metadata with OAuth Authorization
  Server metadata fallback.
- `oauth userinfo` to call the OIDC UserInfo endpoint with a bearer token.

## [0.5.0] - 2026-09-27

### Added

- RFC 8628 device authorization grant: `oauth device-code` and
  `oauth device-token` (single attempt or `--wait` polling).

## [0.4.0] - 2026-09-23

### Added

- `jwt sign` for HMAC-signed test tokens.
- `oauth introspect` (RFC 7662) and `oauth revoke` (RFC 7009).

## [0.3.0] - 2026-09-13

### Added

- `jwt verify` with an HMAC secret or a JWKS URL, plus `iss`, `aud`, and
  expiry checks.
- `oauth client-credentials` grant.

## [0.2.0] - 2026-09-10

### Added

- `oauth pkce` to generate a code verifier, S256 challenge, and state.
- `oauth refresh` for the refresh-token grant.

### Changed

- Rewritten in Java 17 with Picocli and Nimbus JOSE+JWT (2026-09-11),
  replacing the original Node.js implementation.

## [0.1.0] - 2026-09-08

### Added

- Initial CLI: `jwt decode`, `jwt inspect`, `oauth authorize-url`, and
  `oauth exchange`.
