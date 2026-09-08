/**
 * JWT decode and inspect helpers.
 * Uses the `jose` package for base64url decoding and claim parsing.
 * Signature verification is intentionally out of scope for this CLI;
 * tokens are treated as opaque payloads for local inspection only.
 */

import { decodeJwt, decodeProtectedHeader } from 'jose';

/**
 * Decode a JWT without verifying the signature.
 * @param {string} token
 * @returns {{ header: object, payload: object }}
 */
export function decode(token) {
  if (typeof token !== 'string' || !token.trim()) {
    throw new Error('JWT token must be a non-empty string');
  }
  const trimmed = token.trim();
  const parts = trimmed.split('.');
  if (parts.length < 2 || parts.length > 3) {
    throw new Error('Invalid JWT: expected 2 or 3 dot-separated segments');
  }

  let header;
  let payload;
  try {
    header = decodeProtectedHeader(trimmed);
    payload = decodeJwt(trimmed);
  } catch (err) {
    throw new Error(`Failed to decode JWT: ${err.message}`);
  }

  return { header, payload };
}

/**
 * Summarize claims useful for quick inspection (exp, iat, nbf, etc.).
 * @param {string} token
 * @param {{ now?: number }} [options]
 * @returns {object}
 */
export function inspect(token, options = {}) {
  const nowSec =
    typeof options.now === 'number'
      ? options.now
      : Math.floor(Date.now() / 1000);

  const { header, payload } = decode(token);
  const claims = { ...payload };

  const summary = {
    alg: header.alg ?? null,
    typ: header.typ ?? null,
    kid: header.kid ?? null,
    iss: claims.iss ?? null,
    sub: claims.sub ?? null,
    aud: claims.aud ?? null,
    jti: claims.jti ?? null,
  };

  const timeClaims = {};
  for (const key of ['exp', 'iat', 'nbf']) {
    if (typeof claims[key] === 'number') {
      const iso = new Date(claims[key] * 1000).toISOString();
      timeClaims[key] = { unix: claims[key], iso };
    }
  }

  let expired = null;
  let expiresInSeconds = null;
  if (typeof claims.exp === 'number') {
    expiresInSeconds = claims.exp - nowSec;
    expired = expiresInSeconds <= 0;
  }

  let notYetValid = null;
  if (typeof claims.nbf === 'number') {
    notYetValid = claims.nbf > nowSec;
  }

  return {
    header,
    payload: claims,
    summary,
    time: timeClaims,
    expired,
    expiresInSeconds,
    notYetValid,
    evaluatedAt: nowSec,
  };
}
