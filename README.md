# jwt-oauth-cli

Java CLI to decode, inspect, verify, and sign JWTs, build OAuth 2.0 authorize
URLs, generate PKCE pairs, exchange authorization codes, refresh tokens, request
client-credentials tokens, run the device authorization grant, introspect
tokens, revoke tokens, discover OIDC/OAuth metadata, and call UserInfo locally.
Token-endpoint calls support `client_secret_basic`, `client_secret_post`,
`private_key_jwt`, and `client_secret_jwt` client authentication.

Requires JDK 17+.

## Build

```bash
mvn -q package
```

The shaded jar is written to `target/jwt-oauth-cli-0.9.0.jar`.

```bash
java -jar target/jwt-oauth-cli-0.9.0.jar --help
```

Optional install-style alias:

```bash
alias jwt-oauth-cli='java -jar /path/to/jwt-oauth-cli-0.9.0.jar'
```

## Usage

### JWT decode

Decode header and payload (no signature verification):

```bash
java -jar target/jwt-oauth-cli-0.9.0.jar jwt decode eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.
```

### JWT inspect

Summarize claims and expiration:

```bash
java -jar target/jwt-oauth-cli-0.9.0.jar jwt inspect eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIiwiZXhwIjoxODkzNDU2MDAwfQ.
```

### JWT verify

Verify a signature locally. Use an HMAC secret for HS256/HS384/HS512, or a JWKS
URL for RS*/ES* (matched by `kid` and `alg`). Prefer
`JWT_OAUTH_HMAC_SECRET` over `--secret`.

HMAC:

```bash
export JWT_OAUTH_HMAC_SECRET=your-hmac-secret
java -jar target/jwt-oauth-cli-0.9.0.jar jwt verify "$TOKEN" \
  --iss https://issuer.example \
  --aud api \
  --exp-leeway-seconds 60
```

JWKS:

```bash
java -jar target/jwt-oauth-cli-0.9.0.jar jwt verify "$TOKEN" \
  --jwks-url https://auth.example/.well-known/jwks.json \
  --iss https://issuer.example \
  --aud api \
  --compact
```

Successful output includes `valid`, `header`, `payload`, `claimsChecked`, and
`algorithm`. Failures print a clear error and exit non-zero.


### JWT sign

Create an HMAC-signed JWT for local testing (pairs with `jwt verify`). Prefer
`JWT_OAUTH_HMAC_SECRET` over `--secret`. Algorithms: HS256 (default), HS384,
HS512.

```bash
export JWT_OAUTH_HMAC_SECRET=your-hmac-secret
java -jar target/jwt-oauth-cli-0.9.0.jar jwt sign \
  --sub user-1 \
  --iss https://issuer.example \
  --aud api \
  --exp-seconds 3600 \
  --claim role=admin \
  --kid local-1
```

Random `jti` and compact output:

```bash
java -jar target/jwt-oauth-cli-0.9.0.jar jwt sign \
  --sub user-1 \
  --alg HS512 \
  --jti-random \
  --compact
```

Successful output includes `token`, `header`, and `payload`.


### Asymmetric sign and offline verify

`jwt sign --jwk-file` signs with a private RSA or EC JWK (for example the `jwk`
output of `jwt keygen`). The algorithm defaults to the JWK's `alg`, else RS256
for RSA or the curve's ES* for EC; the JWK `kid` is copied into the header.
`jwt verify --jwks-file` checks the signature against a local JWKS (or a single
public JWK) with no network call.

```bash
jwt-oauth-cli jwt keygen --alg ES256 --kid local-1 > keys.json
jq '.jwk'  keys.json > private.jwk.json
jq '.jwks' keys.json > jwks.json

TOKEN=$(jwt-oauth-cli jwt sign --jwk-file private.jwk.json --sub alice --aud api -c | jq -r .token)
jwt-oauth-cli jwt verify "$TOKEN" --jwks-file jwks.json --aud api
```

Keep private JWK files out of source control.

### JWT keygen

Generate a signing key as a JWK for local testing. RSA and EC keys also print
the public JWK and a ready-to-serve JWKS (useful with `jwt verify --jwks`).
Algorithms: RS256/384/512, PS256/384/512, ES256/384/512, HS256/384/512. The
`kid` defaults to the RFC 7638 thumbprint.

```bash
java -jar target/jwt-oauth-cli-0.9.0.jar jwt keygen --alg ES256 --kid local-ec
java -jar target/jwt-oauth-cli-0.9.0.jar jwt keygen --alg RS256 --rsa-bits 3072 --public-only > jwks.json
```

Output includes `alg`, `kty`, `kid`, `jwk` (private) and, for RSA/EC,
`publicJwk` and `jwks`. Keep private output out of source control.

### OAuth authorize URL

```bash
java -jar target/jwt-oauth-cli-0.9.0.jar oauth authorize-url \
  --authorization-endpoint https://auth.example/authorize \
  --client-id my-client \
  --redirect-uri http://127.0.0.1:8080/callback \
  --scope "openid profile" \
  --state xyz
```

Optional PKCE (pair the challenge with values from `oauth pkce`):

```bash
java -jar target/jwt-oauth-cli-0.9.0.jar oauth authorize-url \
  --authorization-endpoint https://auth.example/authorize \
  --client-id my-client \
  --redirect-uri http://127.0.0.1:8080/callback \
  --code-challenge CHALLENGE \
  --code-challenge-method S256 \
  --state STATE
```

### OAuth PKCE pair

Generate a `code_verifier`, S256 `code_challenge`, and random `state`:

```bash
java -jar target/jwt-oauth-cli-0.9.0.jar oauth pkce
```

Compact JSON:

```bash
java -jar target/jwt-oauth-cli-0.9.0.jar oauth pkce --compact
```

### OAuth code exchange

Exchanges an authorization code at the token endpoint via POST
(`application/x-www-form-urlencoded`). Prefer passing the client secret through
the `JWT_OAUTH_CLIENT_SECRET` environment variable rather than the CLI flag.

```bash
export JWT_OAUTH_CLIENT_SECRET=your-secret
java -jar target/jwt-oauth-cli-0.9.0.jar oauth exchange \
  --token-endpoint https://auth.example/token \
  --code AUTH_CODE \
  --redirect-uri http://127.0.0.1:8080/callback \
  --client-id my-client
```

With PKCE verifier:

```bash
java -jar target/jwt-oauth-cli-0.9.0.jar oauth exchange \
  --token-endpoint https://auth.example/token \
  --code AUTH_CODE \
  --redirect-uri http://127.0.0.1:8080/callback \
  --client-id my-client \
  --code-verifier VERIFIER
```

### OAuth refresh token

Refresh an access token using the `refresh_token` grant. Client secret handling
matches `oauth exchange` (env `JWT_OAUTH_CLIENT_SECRET` preferred; never logged).

```bash
export JWT_OAUTH_CLIENT_SECRET=your-secret
java -jar target/jwt-oauth-cli-0.9.0.jar oauth refresh \
  --token-endpoint https://auth.example/token \
  --refresh-token REFRESH_TOKEN \
  --client-id my-client
```

Optional scope and compact output:

```bash
java -jar target/jwt-oauth-cli-0.9.0.jar oauth refresh \
  --token-endpoint https://auth.example/token \
  --refresh-token REFRESH_TOKEN \
  --client-id my-client \
  --scope "openid profile" \
  --compact
```

### OAuth client credentials

Request an access token using the `client_credentials` grant. Prefer
`JWT_OAUTH_CLIENT_SECRET` over `--client-secret`.

```bash
export JWT_OAUTH_CLIENT_SECRET=your-secret
java -jar target/jwt-oauth-cli-0.9.0.jar oauth client-credentials \
  --token-endpoint https://auth.example/token \
  --client-id my-client \
  --scope "api.read"
```

Compact JSON:

```bash
java -jar target/jwt-oauth-cli-0.9.0.jar oauth client-credentials \
  --token-endpoint https://auth.example/token \
  --client-id my-client \
  --compact
```


### OAuth client authentication

Every command that authenticates the client (`exchange`, `refresh`,
`client-credentials`, `device-code`, `device-token`, `introspect`, `revoke`)
accepts the same flags:

| Flag | Meaning |
| --- | --- |
| `--client-auth basic` | `Authorization: Basic` header (RFC 6749 §2.3.1); secret is not put in the body |
| `--client-auth post` | `client_secret` in the form body (secret required) |
| `--client-auth private_key_jwt` | Signed client assertion from `--client-jwk-file` (RS*/PS*/ES*), no secret sent |
| `--client-auth client_secret_jwt` | Client assertion signed with the client secret (HS256 by default), secret not sent |
| `--client-jwk-file FILE` | Private RSA/EC JWK, or a JWKS holding exactly one private key |
| `--assertion-alg ALG` | Override the assertion algorithm |
| `--assertion-aud AUD` | Override the assertion audience (default: the endpoint being called) |
| `--assertion-lifetime SECONDS` | Assertion lifetime, default 60 |

Without `--client-auth`, requests are unchanged from earlier releases:
`client_id` plus `client_secret` in the body when a secret is supplied.

The JWT methods follow RFC 7523 and OIDC Core section 9. The assertion has
`iss` and `sub` set to the client ID, `aud` set to the endpoint, a random
`jti`, `iat`, and `exp`; the JWK `kid` is copied into the header. The request
carries `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer`
and `client_assertion`. A fresh assertion is built for every request, including
each poll of `device-token --wait`.

`private_key_jwt` with a key from `jwt keygen` (register the public `jwks` with
your authorization server):

```bash
jwt-oauth-cli jwt keygen --alg ES256 --kid my-client-key > keys.json
jq '.jwk' keys.json > client.jwk.json

java -jar target/jwt-oauth-cli-0.9.0.jar oauth client-credentials \
  --token-endpoint https://auth.example/oauth2/token \
  --client-id my-service \
  --client-auth private_key_jwt \
  --client-jwk-file client.jwk.json \
  --scope "api.read"
```

`client_secret_jwt` on a refresh, with an audience the server expects
(some servers want the issuer rather than the token endpoint):

```bash
export JWT_OAUTH_CLIENT_SECRET=a-client-secret-of-at-least-32-bytes
java -jar target/jwt-oauth-cli-0.9.0.jar oauth refresh \
  --token-endpoint https://auth.example/oauth2/token \
  --refresh-token REFRESH_TOKEN \
  --client-id my-client \
  --client-auth client_secret_jwt \
  --assertion-aud https://auth.example
```

HTTP Basic instead of a body secret:

```bash
export JWT_OAUTH_CLIENT_SECRET=your-secret
java -jar target/jwt-oauth-cli-0.9.0.jar oauth introspect \
  --introspection-endpoint https://auth.example/introspect \
  --token ACCESS_TOKEN \
  --client-id my-resource-server \
  --client-auth basic
```

### OAuth client assertion

Print a client assertion without calling any endpoint, handy for checking what
the server will receive or for pasting into another tool. Uses
`private_key_jwt` when `--client-jwk-file` is given, otherwise
`client_secret_jwt` with `--client-secret` / `JWT_OAUTH_CLIENT_SECRET`.

```bash
java -jar target/jwt-oauth-cli-0.9.0.jar oauth client-assertion \
  --client-id my-service \
  --aud https://auth.example/oauth2/token \
  --client-jwk-file client.jwk.json
```

Output includes `client_assertion_type`, `client_assertion`, and the decoded
`header` and `payload`. Combine with `jwt inspect` to check timing claims.


### OAuth device code

RFC 8628 device authorization start. POSTs `application/x-www-form-urlencoded`
and prints `device_code`, `user_code`, `verification_uri`, `expires_in`, and
`interval` (5 when the server omits it). `verification_uri_complete` is included
when the server sends it. Prefer `JWT_OAUTH_CLIENT_SECRET` over
`--client-secret` for confidential clients.

```bash
java -jar target/jwt-oauth-cli-0.9.0.jar oauth device-code \
  --device-authorization-endpoint https://auth.example/device \
  --client-id my-client \
  --scope "openid profile"
```

### OAuth device token

Exchange a device code at the token endpoint
(`grant_type=urn:ietf:params:oauth:grant-type:device_code`). A single attempt
exits 0 when an access token is returned and 2 when the user has not finished
(`authorization_pending` or `slow_down`), so a script can retry. Terminal
errors such as `expired_token` and `access_denied` exit 1.

```bash
java -jar target/jwt-oauth-cli-0.9.0.jar oauth device-token \
  --token-endpoint https://auth.example/token \
  --device-code DEVICE_CODE \
  --client-id my-client
```

`--wait` polls until a token is issued, a terminal error occurs, or
`--max-wait-seconds` (default 600) elapses. Sleep `--interval` seconds between
attempts (default 5, typically the `interval` from `oauth device-code`). On
`slow_down`, use `interval` from that response when present; otherwise add 5
seconds to the current sleep.

```bash
export JWT_OAUTH_CLIENT_SECRET=your-secret
java -jar target/jwt-oauth-cli-0.9.0.jar oauth device-token \
  --token-endpoint https://auth.example/token \
  --device-code DEVICE_CODE \
  --client-id my-client \
  --interval 5 \
  --max-wait-seconds 600 \
  --wait
```

### OAuth introspect

RFC 7662 token introspection. POSTs `application/x-www-form-urlencoded` to the
introspection endpoint. Prefer `JWT_OAUTH_CLIENT_SECRET` over `--client-secret`.

```bash
export JWT_OAUTH_CLIENT_SECRET=your-secret
java -jar target/jwt-oauth-cli-0.9.0.jar oauth introspect \
  --introspection-endpoint https://auth.example/introspect \
  --token ACCESS_TOKEN \
  --token-type-hint access_token \
  --client-id my-client
```

### OAuth revoke

RFC 7009 token revocation. Treats HTTP 200/204 as success and prints
`{"revoked": true, "status": ...}`.

```bash
export JWT_OAUTH_CLIENT_SECRET=your-secret
java -jar target/jwt-oauth-cli-0.9.0.jar oauth revoke \
  --revocation-endpoint https://auth.example/revoke \
  --token REFRESH_TOKEN \
  --token-type-hint refresh_token \
  --client-id my-client \
  --compact
```


### OAuth discover

Fetch OpenID Provider metadata (`/.well-known/openid-configuration`). If that
document returns HTTP 404, fall back to OAuth Authorization Server metadata
(`/.well-known/oauth-authorization-server`). Pass `--metadata-url` to hit a
document URL directly. Output includes common endpoints and capability arrays
when the server advertises them.

```bash
java -jar target/jwt-oauth-cli-0.9.0.jar oauth discover \
  --issuer https://auth.example
```

Direct metadata URL and compact JSON:

```bash
java -jar target/jwt-oauth-cli-0.9.0.jar oauth discover \
  --metadata-url https://auth.example/.well-known/openid-configuration \
  --compact
```

### OAuth userinfo

Call the OIDC UserInfo endpoint with a bearer access token. Prefer
`JWT_OAUTH_ACCESS_TOKEN` over `--access-token` (never logged).

```bash
export JWT_OAUTH_ACCESS_TOKEN=ACCESS_TOKEN
java -jar target/jwt-oauth-cli-0.9.0.jar oauth userinfo \
  --userinfo-endpoint https://auth.example/userinfo
```

Compact JSON:

```bash
java -jar target/jwt-oauth-cli-0.9.0.jar oauth userinfo \
  --userinfo-endpoint https://auth.example/userinfo \
  --access-token ACCESS_TOKEN \
  --compact
```

## Library API

Core helpers live under `dev.rmkr.jwtoauthcli`:

- `jwt.JwtSupport.decode(token)` / `inspect(token)` / `inspect(token, nowSec)`
- `jwt.JwtSupport.verify(token, options)` — HMAC (`secret`) or JWKS (`jwksUrl`);
  optional `iss`, `aud`, `expLeewaySeconds`, injectable `jwksFetcher`
- `jwt.JwtSupport.sign(options)` — HMAC HS256/HS384/HS512; returns `token`,
  `header`, `payload`
- `oauth.OauthSupport.buildAuthorizeUrl(params)`
- `oauth.OauthSupport.generatePkce()` / `generatePkce(verifierBytes)`
- `oauth.OauthSupport.exchangeCode(params)` / `exchangeCode(params, formPoster)`
- `oauth.OauthSupport.refreshToken(params)` / `refreshToken(params, formPoster)`
- `oauth.OauthSupport.clientCredentials(params)` /
  `clientCredentials(params, formPoster)`
- `oauth.OauthSupport.deviceAuthorization(params)` /
  `deviceAuthorization(params, formPoster)`
- `oauth.OauthSupport.deviceToken(params)` / `deviceToken(params, formPoster)`
- `oauth.OauthSupport.introspect(params)` / `introspect(params, formPoster)`
- `oauth.OauthSupport.revoke(params)` / `revoke(params, formPoster)`
- `oauth.OauthSupport.discover(params)` / `discover(params, jsonGetClient)`
- `oauth.OauthSupport.userinfo(params)` / `userinfo(params, jsonGetClient)`
- `oauth.OauthSupport.preferEnvOverFlag(envValue, flagValue)`
- `oauth.ClientAssertionSupport.buildAssertion(options)` — RFC 7523 client
  assertion (`private_key_jwt` / `client_secret_jwt`). The token, device,
  introspection, and revocation helpers above also accept `clientAuth`,
  `clientJwk` / `clientJwkFile`, `assertionAlg`, `assertionAudience`, and
  `assertionLifetimeSeconds` params.

JWT helpers use [Nimbus JOSE+JWT](https://connect2id.com/products/nimbus-jose-jwt).
Token HTTP calls use `java.net.http.HttpClient` via `http.FormPoster` (injectable
in tests). JSON GETs (discovery / UserInfo) use `http.JsonGetClient`. JWKS
fetches use `http.JwksFetcher` (also injectable).

## Development

```bash
mvn test
mvn package
```

## Extending the CLI

When adding commands or flags:

1. Put reusable logic in `JwtSupport` or `OauthSupport`.
2. Wire the command under `cli` with Picocli (subcommand of `jwt` or `oauth`).
3. Add JUnit 5 coverage for URL/body construction and claim parsing.
4. Keep defaults conservative: no hardcoded IdP hosts, no logging of secrets or
   tokens, POST form bodies for token requests.
5. Prefer Nimbus for any new JWT work; document any temporary fallback clearly.
6. Update this README with a short usage example for each new command.

## License

MIT
