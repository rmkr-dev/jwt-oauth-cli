import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { decode, inspect } from '../src/jwt.js';

/** Build an unsigned JWT-like token from JSON header/payload (alg none). */
function makeToken(header, payload) {
  const enc = (obj) =>
    Buffer.from(JSON.stringify(obj), 'utf8')
      .toString('base64url');
  return `${enc(header)}.${enc(payload)}.`;
}

describe('jwt.decode', () => {
  it('decodes header and payload', () => {
    const token = makeToken(
      { alg: 'none', typ: 'JWT' },
      { sub: 'user-1', iss: 'https://issuer.example', aud: 'api' }
    );
    const { header, payload } = decode(token);
    assert.equal(header.alg, 'none');
    assert.equal(header.typ, 'JWT');
    assert.equal(payload.sub, 'user-1');
    assert.equal(payload.iss, 'https://issuer.example');
    assert.equal(payload.aud, 'api');
  });

  it('rejects empty input', () => {
    assert.throws(() => decode(''), /non-empty/);
  });

  it('rejects malformed segments', () => {
    assert.throws(() => decode('onlyone'), /Invalid JWT/);
  });
});

describe('jwt.inspect', () => {
  it('reports expiration relative to a fixed now', () => {
    const now = 1_700_000_000;
    const token = makeToken(
      { alg: 'HS256', typ: 'JWT', kid: 'k1' },
      {
        sub: 'abc',
        iss: 'https://issuer.example',
        exp: now + 60,
        iat: now - 60,
        nbf: now - 30,
      }
    );
    const result = inspect(token, { now });
    assert.equal(result.expired, false);
    assert.equal(result.expiresInSeconds, 60);
    assert.equal(result.notYetValid, false);
    assert.equal(result.summary.sub, 'abc');
    assert.equal(result.summary.kid, 'k1');
    assert.equal(result.time.exp.unix, now + 60);
    assert.ok(result.time.exp.iso);
  });

  it('marks expired tokens', () => {
    const now = 1_700_000_000;
    const token = makeToken(
      { alg: 'none' },
      { exp: now - 1 }
    );
    const result = inspect(token, { now });
    assert.equal(result.expired, true);
    assert.ok(result.expiresInSeconds < 0);
  });
});
