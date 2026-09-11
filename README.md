# jwt-oauth-cli

Java CLI to decode and inspect JWTs, build OAuth 2.0 authorize URLs, generate
PKCE pairs, exchange authorization codes, and refresh tokens locally.

Requires JDK 17+.

## Build

```bash
mvn -q package
```

The shaded jar is written to `target/jwt-oauth-cli-0.2.0.jar`.

```bash
java -jar target/jwt-oauth-cli-0.2.0.jar --help
```

Optional install-style alias:

```bash
alias jwt-oauth-cli='java -jar /path/to/jwt-oauth-cli-0.2.0.jar'
```

## Usage

### JWT decode

Decode header and payload (no signature verification):

```bash
java -jar target/jwt-oauth-cli-0.2.0.jar jwt decode eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.
```

### JWT inspect

Summarize claims and expiration:

```bash
java -jar target/jwt-oauth-cli-0.2.0.jar jwt inspect eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIiwiZXhwIjoxODkzNDU2MDAwfQ.
```

### OAuth authorize URL

```bash
java -jar target/jwt-oauth-cli-0.2.0.jar oauth authorize-url \
  --authorization-endpoint https://auth.example/authorize \
  --client-id my-client \
  --redirect-uri http://127.0.0.1:8080/callback \
  --scope "openid profile" \
  --state xyz
```

Optional PKCE (pair the challenge with values from `oauth pkce`):

```bash
java -jar target/jwt-oauth-cli-0.2.0.jar oauth authorize-url \
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
java -jar target/jwt-oauth-cli-0.2.0.jar oauth pkce
```

Compact JSON:

```bash
java -jar target/jwt-oauth-cli-0.2.0.jar oauth pkce --compact
```

### OAuth code exchange

Exchanges an authorization code at the token endpoint via POST
(`application/x-www-form-urlencoded`). Prefer passing the client secret through
the `JWT_OAUTH_CLIENT_SECRET` environment variable rather than the CLI flag.

```bash
export JWT_OAUTH_CLIENT_SECRET=your-secret
java -jar target/jwt-oauth-cli-0.2.0.jar oauth exchange \
  --token-endpoint https://auth.example/token \
  --code AUTH_CODE \
  --redirect-uri http://127.0.0.1:8080/callback \
  --client-id my-client
```

With PKCE verifier:

```bash
java -jar target/jwt-oauth-cli-0.2.0.jar oauth exchange \
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
java -jar target/jwt-oauth-cli-0.2.0.jar oauth refresh \
  --token-endpoint https://auth.example/token \
  --refresh-token REFRESH_TOKEN \
  --client-id my-client
```

Optional scope and compact output:

```bash
java -jar target/jwt-oauth-cli-0.2.0.jar oauth refresh \
  --token-endpoint https://auth.example/token \
  --refresh-token REFRESH_TOKEN \
  --client-id my-client \
  --scope "openid profile" \
  --compact
```

## Library API

Core helpers live under `dev.rmkr.jwtoauthcli`:

- `jwt.JwtSupport.decode(token)` / `inspect(token)` / `inspect(token, nowSec)`
- `oauth.OauthSupport.buildAuthorizeUrl(params)`
- `oauth.OauthSupport.generatePkce()` / `generatePkce(verifierBytes)`
- `oauth.OauthSupport.exchangeCode(params)` / `exchangeCode(params, formPoster)`
- `oauth.OauthSupport.refreshToken(params)` / `refreshToken(params, formPoster)`

JWT helpers use [Nimbus JOSE+JWT](https://connect2id.com/products/nimbus-jose-jwt).
Signature verification is intentionally out of scope for this CLI. Token HTTP
calls use `java.net.http.HttpClient` via `http.FormPoster` (injectable in tests).

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
