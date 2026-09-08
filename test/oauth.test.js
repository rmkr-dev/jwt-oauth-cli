import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { buildAuthorizeUrl, exchangeCode } from '../src/oauth.js';

describe('oauth.buildAuthorizeUrl', () => {
  it('builds a standard authorization URL', () => {
    const url = buildAuthorizeUrl({
      authorizationEndpoint: 'https://auth.example/authorize',
      clientId: 'my-client',
      redirectUri: 'http://127.0.0.1:8080/callback',
      scope: 'openid profile',
      state: 'xyz',
    });
    const parsed = new URL(url);
    assert.equal(parsed.origin + parsed.pathname, 'https://auth.example/authorize');
    assert.equal(parsed.searchParams.get('response_type'), 'code');
    assert.equal(parsed.searchParams.get('client_id'), 'my-client');
    assert.equal(
      parsed.searchParams.get('redirect_uri'),
      'http://127.0.0.1:8080/callback'
    );
    assert.equal(parsed.searchParams.get('scope'), 'openid profile');
    assert.equal(parsed.searchParams.get('state'), 'xyz');
  });

  it('joins array scopes and supports PKCE', () => {
    const url = buildAuthorizeUrl({
      authorizationEndpoint: 'https://auth.example/oauth/authorize',
      clientId: 'c',
      redirectUri: 'http://localhost/cb',
      scope: ['openid', 'email'],
      codeChallenge: 'challenge-value',
    });
    const parsed = new URL(url);
    assert.equal(parsed.searchParams.get('scope'), 'openid email');
    assert.equal(parsed.searchParams.get('code_challenge'), 'challenge-value');
    assert.equal(parsed.searchParams.get('code_challenge_method'), 'S256');
  });

  it('requires core parameters', () => {
    assert.throws(
      () =>
        buildAuthorizeUrl({
          clientId: 'c',
          redirectUri: 'http://localhost/cb',
        }),
      /authorizationEndpoint/
    );
  });
});

describe('oauth.exchangeCode', () => {
  it('POSTs form body and returns JSON', async () => {
    const calls = [];
    const fetchImpl = async (url, init) => {
      calls.push({ url, init });
      return {
        ok: true,
        status: 200,
        text: async () =>
          JSON.stringify({
            access_token: 'atok',
            token_type: 'Bearer',
            expires_in: 3600,
          }),
      };
    };

    const result = await exchangeCode({
      tokenEndpoint: 'https://auth.example/token',
      code: 'auth-code',
      redirectUri: 'http://127.0.0.1:8080/callback',
      clientId: 'my-client',
      clientSecret: 's3cret',
      codeVerifier: 'verifier',
      fetchImpl,
    });

    assert.equal(result.access_token, 'atok');
    assert.equal(calls.length, 1);
    assert.equal(calls[0].url, 'https://auth.example/token');
    assert.equal(calls[0].init.method, 'POST');
    assert.match(
      calls[0].init.headers['content-type'],
      /application\/x-www-form-urlencoded/
    );
    const body = new URLSearchParams(calls[0].init.body);
    assert.equal(body.get('grant_type'), 'authorization_code');
    assert.equal(body.get('code'), 'auth-code');
    assert.equal(body.get('client_id'), 'my-client');
    assert.equal(body.get('client_secret'), 's3cret');
    assert.equal(body.get('code_verifier'), 'verifier');
  });

  it('surfaces token endpoint errors', async () => {
    const fetchImpl = async () => ({
      ok: false,
      status: 400,
      text: async () =>
        JSON.stringify({
          error: 'invalid_grant',
          error_description: 'code expired',
        }),
    });

    await assert.rejects(
      () =>
        exchangeCode({
          tokenEndpoint: 'https://auth.example/token',
          code: 'bad',
          redirectUri: 'http://127.0.0.1/cb',
          clientId: 'c',
          fetchImpl,
        }),
      /code expired/
    );
  });
});
