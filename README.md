# jwt-oauth-cli

Java CLI to decode, inspect, verify, and sign JWTs, build OAuth 2.0 authorize
URLs, generate PKCE pairs, exchange authorization codes, refresh tokens, request
client-credentials tokens, introspect tokens, and revoke tokens locally.

Requires JDK 17+.

## Build

```bash
mvn -q package
```

The shaded jar is written to `target/jwt-oauth-cli-0.4.0.jar`.

```bash
java -jar target/jwt-oauth-cli-0.4.0.jar --help
```

Optional install-style alias:

```bash
alias jwt-oauth-cli='java -jar /path/to/jwt-oauth-cli-0.4.0.jar'
```

## Usage

### JWT decode

Decode header and payload (no signature verification):

```bash
java -jar target/jwt-oauth-cli-0.4.0.jar jwt decode eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.
```

### JWT inspect

Summarize claims and expiration:

```bash
java -jar target/jwt-oauth-cli-0.4.0.jar jwt inspect eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIiwiZXhwIjoxODkzNDU2MDAwfQ.
```

### JWT verify

Verify a signature locally. Use an HMAC secret for HS256/HS384/HS512, or a JWKS
URL for RS*/ES* (matched by `kid` and `alg`). Prefer
`JWT_OAUTH_HMAC_SECRET` over `--secret`.

HMAC:

```bash
export JWT_OAUTH_HMAC_SECRET=your-hmac-secret
java -jar target/jwt-oauth-cli-0.4.0.jar jwt verify "$TOKEN" \
  --iss https://issuer.example \
  --aud api \
  --exp-leeway-seconds 60
```

JWKS:

```bash
java -jar target/jwt-oauth-cli-0.4.0.jar jwt verify "$TOKEN" \
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
java -jar target/jwt-oauth-cli-0.4.0.jar jwt sign \
  --sub user-1 \
  --iss https://issuer.example \
  --aud api \
  --exp-seconds 3600 \
  --claim role=admin \
  --kid local-1
```

Random `jti` and compact output:

```bash
java -jar target/jwt-oauth-cli-0.4.0.jar jwt sign \
  --sub user-1 \
  --alg HS512 \
  --jti-random \
  --compact
```

Successful output includes `token`, `header`, and `payload`.

### OAuth authorize URL

```bash
java -jar target/jwt-oauth-cli-0.4.0.jar oauth authorize-url \
  --authorization-endpoint https://auth.example/authorize \
  --client-id my-client \
  --redirect-uri http://127.0.0.1:8080/callback \
  --scope "openid profile" \
  --state xyz
```

Optional PKCE (pair the challenge with values from `oauth pkce`):

```bash
java -jar target/jwt-oauth-cli-0.4.0.jar oauth authorize-url \
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
java -jar target/jwt-oauth-cli-0.4.0.jar oauth pkce
```

Compact JSON:

```bash
java -jar target/jwt-oauth-cli-0.4.0.jar oauth pkce --compact
```

### OAuth code exchange

Exchanges an authorization code at the token endpoint via POST
(`application/x-www-form-urlencoded`). Prefer passing the client secret through
the `JWT_OAUTH_CLIENT_SECRET` environment variable rather than the CLI flag.

```bash
export JWT_OAUTH_CLIENT_SECRET=your-secret
java -jar target/jwt-oauth-cli-0.4.0.jar oauth exchange \
  --token-endpoint https://auth.example/token \
  --code AUTH_CODE \
  --redirect-uri http://127.0.0.1:8080/callback \
  --client-id my-client
```

With PKCE verifier:

```bash
java -jar target/jwt-oauth-cli-0.4.0.jar oauth exchange \
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
java -jar target/jwt-oauth-cli-0.4.0.jar oauth refresh \
  --token-endpoint https://auth.example/token \
  --refresh-token REFRESH_TOKEN \
  --client-id my-client
```

Optional scope and compact output:

```bash
java -jar target/jwt-oauth-cli-0.4.0.jar oauth refresh \
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
java -jar target/jwt-oauth-cli-0.4.0.jar oauth client-credentials \
  --token-endpoint https://auth.example/token \
  --client-id my-client \
  --scope "api.read"
```

Compact JSON:

```bash
java -jar target/jwt-oauth-cli-0.4.0.jar oauth client-credentials \
  --token-endpoint https://auth.example/token \
  --client-id my-client \
  --compact
```


### OAuth introspect

RFC 7662 token introspection. POSTs `application/x-www-form-urlencoded` to the
introspection endpoint. Prefer `JWT_OAUTH_CLIENT_SECRET` over `--client-secret`.

```bash
export JWT_OAUTH_CLIENT_SECRET=your-secret
java -jar target/jwt-oauth-cli-0.4.0.jar oauth introspect \
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
java -jar target/jwt-oauth-cli-0.4.0.jar oauth revoke \
  --revocation-endpoint https://auth.example/revoke \
  --token REFRESH_TOKEN \
  --token-type-hint refresh_token \
  --client-id my-client \
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
- `oauth.OauthSupport.introspect(params)` / `introspect(params, formPoster)`
- `oauth.OauthSupport.revoke(params)` / `revoke(params, formPoster)`

JWT helpers use [Nimbus JOSE+JWT](https://connect2id.com/products/nimbus-jose-jwt).
Token HTTP calls use `java.net.http.HttpClient` via `http.FormPoster` (injectable
in tests). JWKS fetches use `http.JwksFetcher` (also injectable).

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
