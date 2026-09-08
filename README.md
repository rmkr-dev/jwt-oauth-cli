# jwt-oauth-cli

Node.js CLI (ESM) to decode and inspect JWTs, build OAuth 2.0 authorize URLs, and exchange authorization codes locally.

Requires Node.js 20+.

## Install

```bash
npm install -g jwt-oauth-cli
```

Or from a clone of this repository:

```bash
npm install
npm link
```

## Usage

### JWT decode

Decode header and payload (no signature verification):

```bash
jwt-oauth-cli jwt decode eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.
```

### JWT inspect

Summarize claims and expiration:

```bash
jwt-oauth-cli jwt inspect eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIiwiZXhwIjoxODkzNDU2MDAwfQ.
```

### OAuth authorize URL

```bash
jwt-oauth-cli oauth authorize-url \
  --authorization-endpoint https://auth.example/authorize \
  --client-id my-client \
  --redirect-uri http://127.0.0.1:8080/callback \
  --scope "openid profile" \
  --state xyz
```

Optional PKCE:

```bash
jwt-oauth-cli oauth authorize-url \
  --authorization-endpoint https://auth.example/authorize \
  --client-id my-client \
  --redirect-uri http://127.0.0.1:8080/callback \
  --code-challenge CHALLENGE \
  --code-challenge-method S256
```

### OAuth code exchange

Exchanges an authorization code at the token endpoint via POST
(`application/x-www-form-urlencoded`). Prefer passing the client secret through
the `JWT_OAUTH_CLIENT_SECRET` environment variable rather than the CLI flag.

```bash
export JWT_OAUTH_CLIENT_SECRET=your-secret
jwt-oauth-cli oauth exchange \
  --token-endpoint https://auth.example/token \
  --code AUTH_CODE \
  --redirect-uri http://127.0.0.1:8080/callback \
  --client-id my-client
```

With PKCE verifier:

```bash
jwt-oauth-cli oauth exchange \
  --token-endpoint https://auth.example/token \
  --code AUTH_CODE \
  --redirect-uri http://127.0.0.1:8080/callback \
  --client-id my-client \
  --code-verifier VERIFIER
```

## Library API

```js
import { decode, inspect, buildAuthorizeUrl, exchangeCode } from 'jwt-oauth-cli';
```

JWT helpers use the [`jose`](https://github.com/panva/jose) package for decoding.
Signature verification is intentionally out of scope for this CLI.

## Development

```bash
npm install
npm run lint
npm test
```

## Extending the CLI (Copilot / Claude Code / Codex)

When adding commands or flags:

1. Put reusable logic in `src/jwt.js` or `src/oauth.js` and export from `src/index.js`.
2. Wire the command in `src/cli.js` with Commander (subcommand under `jwt` or `oauth`).
3. Add `node:test` coverage under `test/` for URL/body construction and claim parsing.
4. Keep defaults conservative: no hardcoded IdP hosts, no logging of secrets or tokens, POST form bodies for token requests.
5. Prefer `jose` for any new JWT work; document any temporary fallback clearly in code comments and the README.
6. Update this README with a short usage example for each new command.

## License

MIT
