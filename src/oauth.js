/**
 * OAuth 2.0 helpers: authorize URL construction, local code exchange,
 * PKCE generation, and refresh-token grant.
 * Defaults are intentionally conservative (no client secret in query strings,
 * POST form body for token requests, no automatic redirects).
 */

import { createHash, randomBytes } from 'node:crypto';

/**
 * Base64url encode a Buffer/Uint8Array without padding (RFC 7636).
 * @param {Buffer|Uint8Array} buf
 * @returns {string}
 */
function base64UrlEncode(buf) {
  return Buffer.from(buf)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

/**
 * Build an OAuth 2.0 authorization URL.
 * @param {object} params
 * @param {string} params.authorizationEndpoint
 * @param {string} params.clientId
 * @param {string} params.redirectUri
 * @param {string} [params.responseType='code']
 * @param {string|string[]} [params.scope]
 * @param {string} [params.state]
 * @param {string} [params.codeChallenge]
 * @param {string} [params.codeChallengeMethod]
 * @param {Record<string, string>} [params.extra]
 * @returns {string}
 */
export function buildAuthorizeUrl(params) {
  const {
    authorizationEndpoint,
    clientId,
    redirectUri,
    responseType = 'code',
    scope,
    state,
    codeChallenge,
    codeChallengeMethod,
    extra = {},
  } = params;

  if (!authorizationEndpoint || typeof authorizationEndpoint !== 'string') {
    throw new Error('authorizationEndpoint is required');
  }
  if (!clientId || typeof clientId !== 'string') {
    throw new Error('clientId is required');
  }
  if (!redirectUri || typeof redirectUri !== 'string') {
    throw new Error('redirectUri is required');
  }

  let url;
  try {
    url = new URL(authorizationEndpoint);
  } catch {
    throw new Error('authorizationEndpoint must be a valid URL');
  }

  url.searchParams.set('response_type', responseType);
  url.searchParams.set('client_id', clientId);
  url.searchParams.set('redirect_uri', redirectUri);

  if (scope !== undefined && scope !== null && scope !== '') {
    const scopeStr = Array.isArray(scope) ? scope.join(' ') : String(scope);
    url.searchParams.set('scope', scopeStr);
  }
  if (state) {
    url.searchParams.set('state', state);
  }
  if (codeChallenge) {
    url.searchParams.set('code_challenge', codeChallenge);
    url.searchParams.set(
      'code_challenge_method',
      codeChallengeMethod || 'S256'
    );
  }

  for (const [key, value] of Object.entries(extra)) {
    if (value !== undefined && value !== null) {
      url.searchParams.set(key, String(value));
    }
  }

  return url.toString();
}

/**
 * Exchange an authorization code for tokens at the token endpoint.
 * Uses application/x-www-form-urlencoded POST. Client secret is sent in the
 * body only when provided (never logged by this function).
 *
 * @param {object} params
 * @param {string} params.tokenEndpoint
 * @param {string} params.code
 * @param {string} params.redirectUri
 * @param {string} params.clientId
 * @param {string} [params.clientSecret]
 * @param {string} [params.codeVerifier]
 * @param {string} [params.grantType='authorization_code']
 * @param {typeof fetch} [params.fetchImpl] - injectable for tests
 * @returns {Promise<object>} parsed JSON token response
 */
export async function exchangeCode(params) {
  const {
    tokenEndpoint,
    code,
    redirectUri,
    clientId,
    clientSecret,
    codeVerifier,
    grantType = 'authorization_code',
    fetchImpl = globalThis.fetch,
  } = params;

  if (!tokenEndpoint || typeof tokenEndpoint !== 'string') {
    throw new Error('tokenEndpoint is required');
  }
  if (!code || typeof code !== 'string') {
    throw new Error('code is required');
  }
  if (!redirectUri || typeof redirectUri !== 'string') {
    throw new Error('redirectUri is required');
  }
  if (!clientId || typeof clientId !== 'string') {
    throw new Error('clientId is required');
  }
  if (typeof fetchImpl !== 'function') {
    throw new Error('fetch is not available; use Node.js 20+ or provide fetchImpl');
  }

  let endpoint;
  try {
    endpoint = new URL(tokenEndpoint);
  } catch {
    throw new Error('tokenEndpoint must be a valid URL');
  }

  const body = new URLSearchParams();
  body.set('grant_type', grantType);
  body.set('code', code);
  body.set('redirect_uri', redirectUri);
  body.set('client_id', clientId);
  if (clientSecret) {
    body.set('client_secret', clientSecret);
  }
  if (codeVerifier) {
    body.set('code_verifier', codeVerifier);
  }

  const response = await fetchImpl(endpoint.toString(), {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      accept: 'application/json',
    },
    body: body.toString(),
  });

  const text = await response.text();
  let data;
  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    throw new Error(
      `Token endpoint returned non-JSON (HTTP ${response.status}): ${text.slice(0, 200)}`
    );
  }

  if (!response.ok) {
    const errMsg =
      data.error_description ||
      data.error ||
      `HTTP ${response.status}`;
    const error = new Error(`Token exchange failed: ${errMsg}`);
    error.status = response.status;
    error.body = data;
    throw error;
  }

  return data;
}

/**
 * Generate a PKCE code_verifier / code_challenge pair (S256) plus a random state.
 * Verifier is derived from random bytes encoded as base64url (RFC 7636),
 * which yields 43–128 characters from the unreserved URL character set.
 *
 * @param {object} [options]
 * @param {number} [options.verifierBytes=32] - random bytes for the verifier (32 → 43 chars)
 * @returns {{ code_verifier: string, code_challenge: string, code_challenge_method: 'S256', state: string }}
 */
export function generatePkce(options = {}) {
  const verifierBytes = options.verifierBytes ?? 32;
  if (!Number.isInteger(verifierBytes) || verifierBytes < 32 || verifierBytes > 96) {
    throw new Error('verifierBytes must be an integer between 32 and 96');
  }

  const code_verifier = base64UrlEncode(randomBytes(verifierBytes));
  if (code_verifier.length < 43 || code_verifier.length > 128) {
    throw new Error('generated code_verifier length outside RFC 7636 range');
  }

  const challengeDigest = createHash('sha256')
    .update(code_verifier, 'ascii')
    .digest();
  const code_challenge = base64UrlEncode(challengeDigest);
  const state = base64UrlEncode(randomBytes(16));

  return {
    code_verifier,
    code_challenge,
    code_challenge_method: 'S256',
    state,
  };
}

/**
 * Refresh tokens via the refresh_token grant at the token endpoint.
 * Uses application/x-www-form-urlencoded POST. Client secret is sent in the
 * body only when provided (never logged by this function).
 *
 * @param {object} params
 * @param {string} params.tokenEndpoint
 * @param {string} params.refreshToken
 * @param {string} params.clientId
 * @param {string} [params.clientSecret]
 * @param {string|string[]} [params.scope]
 * @param {typeof fetch} [params.fetchImpl] - injectable for tests
 * @returns {Promise<object>} parsed JSON token response
 */
export async function refreshToken(params) {
  const {
    tokenEndpoint,
    refreshToken: refreshTokenValue,
    clientId,
    clientSecret,
    scope,
    fetchImpl = globalThis.fetch,
  } = params;

  if (!tokenEndpoint || typeof tokenEndpoint !== 'string') {
    throw new Error('tokenEndpoint is required');
  }
  if (!refreshTokenValue || typeof refreshTokenValue !== 'string') {
    throw new Error('refreshToken is required');
  }
  if (!clientId || typeof clientId !== 'string') {
    throw new Error('clientId is required');
  }
  if (typeof fetchImpl !== 'function') {
    throw new Error('fetch is not available; use Node.js 20+ or provide fetchImpl');
  }

  let endpoint;
  try {
    endpoint = new URL(tokenEndpoint);
  } catch {
    throw new Error('tokenEndpoint must be a valid URL');
  }

  const body = new URLSearchParams();
  body.set('grant_type', 'refresh_token');
  body.set('refresh_token', refreshTokenValue);
  body.set('client_id', clientId);
  if (clientSecret) {
    body.set('client_secret', clientSecret);
  }
  if (scope !== undefined && scope !== null && scope !== '') {
    const scopeStr = Array.isArray(scope) ? scope.join(' ') : String(scope);
    body.set('scope', scopeStr);
  }

  const response = await fetchImpl(endpoint.toString(), {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      accept: 'application/json',
    },
    body: body.toString(),
  });

  const text = await response.text();
  let data;
  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    throw new Error(
      `Token endpoint returned non-JSON (HTTP ${response.status}): ${text.slice(0, 200)}`
    );
  }

  if (!response.ok) {
    const errMsg =
      data.error_description ||
      data.error ||
      `HTTP ${response.status}`;
    const error = new Error(`Token refresh failed: ${errMsg}`);
    error.status = response.status;
    error.body = data;
    throw error;
  }

  return data;
}
