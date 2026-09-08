#!/usr/bin/env node

import { Command } from 'commander';
import { decode, inspect } from './jwt.js';
import { buildAuthorizeUrl, exchangeCode } from './oauth.js';

const program = new Command();

program
  .name('jwt-oauth-cli')
  .description(
    'Decode/inspect JWTs, build OAuth authorize URLs, and exchange authorization codes locally'
  )
  .version('0.1.0');

const jwtCmd = program.command('jwt').description('JWT utilities');

jwtCmd
  .command('decode')
  .description('Decode a JWT (no signature verification)')
  .argument('<token>', 'JWT string')
  .option('-c, --compact', 'Print compact single-line JSON', false)
  .action((token, options) => {
    try {
      const result = decode(token);
      const json = options.compact
        ? JSON.stringify(result)
        : JSON.stringify(result, null, 2);
      process.stdout.write(json + '\n');
    } catch (err) {
      console.error(err.message);
      process.exitCode = 1;
    }
  });

jwtCmd
  .command('inspect')
  .description('Summarize JWT claims including expiration')
  .argument('<token>', 'JWT string')
  .option('-c, --compact', 'Print compact single-line JSON', false)
  .action((token, options) => {
    try {
      const result = inspect(token);
      const json = options.compact
        ? JSON.stringify(result)
        : JSON.stringify(result, null, 2);
      process.stdout.write(json + '\n');
    } catch (err) {
      console.error(err.message);
      process.exitCode = 1;
    }
  });

const oauthCmd = program.command('oauth').description('OAuth 2.0 utilities');

oauthCmd
  .command('authorize-url')
  .description('Build an OAuth 2.0 authorization URL')
  .requiredOption(
    '--authorization-endpoint <url>',
    'Authorization endpoint URL'
  )
  .requiredOption('--client-id <id>', 'OAuth client ID')
  .requiredOption('--redirect-uri <uri>', 'Redirect URI')
  .option('--response-type <type>', 'response_type', 'code')
  .option('--scope <scope>', 'Space-separated scopes')
  .option('--state <state>', 'Opaque state value')
  .option('--code-challenge <challenge>', 'PKCE code_challenge')
  .option(
    '--code-challenge-method <method>',
    'PKCE code_challenge_method',
    'S256'
  )
  .action((options) => {
    try {
      const url = buildAuthorizeUrl({
        authorizationEndpoint: options.authorizationEndpoint,
        clientId: options.clientId,
        redirectUri: options.redirectUri,
        responseType: options.responseType,
        scope: options.scope,
        state: options.state,
        codeChallenge: options.codeChallenge,
        codeChallengeMethod: options.codeChallenge
          ? options.codeChallengeMethod
          : undefined,
      });
      process.stdout.write(url + '\n');
    } catch (err) {
      console.error(err.message);
      process.exitCode = 1;
    }
  });

oauthCmd
  .command('exchange')
  .description(
    'Exchange an authorization code for tokens (POSTs to the token endpoint)'
  )
  .requiredOption('--token-endpoint <url>', 'Token endpoint URL')
  .requiredOption('--code <code>', 'Authorization code')
  .requiredOption('--redirect-uri <uri>', 'Redirect URI used in authorize')
  .requiredOption('--client-id <id>', 'OAuth client ID')
  .option(
    '--client-secret <secret>',
    'Client secret (sent in POST body only; prefer env JWT_OAUTH_CLIENT_SECRET)'
  )
  .option('--code-verifier <verifier>', 'PKCE code_verifier')
  .option('--grant-type <type>', 'grant_type', 'authorization_code')
  .option('-c, --compact', 'Print compact single-line JSON', false)
  .action(async (options) => {
    try {
      const clientSecret =
        options.clientSecret || process.env.JWT_OAUTH_CLIENT_SECRET || undefined;

      const result = await exchangeCode({
        tokenEndpoint: options.tokenEndpoint,
        code: options.code,
        redirectUri: options.redirectUri,
        clientId: options.clientId,
        clientSecret,
        codeVerifier: options.codeVerifier,
        grantType: options.grantType,
      });

      // Avoid printing secrets if present under uncommon keys; only show response as-is.
      const json = options.compact
        ? JSON.stringify(result)
        : JSON.stringify(result, null, 2);
      process.stdout.write(json + '\n');
    } catch (err) {
      console.error(err.message);
      process.exitCode = 1;
    }
  });

program.parseAsync(process.argv).catch((err) => {
  console.error(err.message || err);
  process.exitCode = 1;
});
