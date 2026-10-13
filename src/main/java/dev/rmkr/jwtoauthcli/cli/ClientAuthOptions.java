package dev.rmkr.jwtoauthcli.cli;

import picocli.CommandLine.Option;

import java.util.Map;

/**
 * Shared client authentication flags for commands that POST client credentials
 * (token, device authorization, introspection, and revocation endpoints).
 * Mixed into each command with {@code @Mixin}. When {@code --client-auth} is
 * omitted, requests are built exactly as before (client_id plus an optional
 * client_secret in the form body).
 */
public class ClientAuthOptions {

  @Option(
      names = "--client-auth",
      paramLabel = "METHOD",
      description =
          "Client authentication: basic, post, private_key_jwt, or client_secret_jwt"
              + " (default: client_id plus client_secret in the body when a secret is given)")
  String clientAuth;

  @Option(
      names = "--client-jwk-file",
      paramLabel = "FILE",
      description = "Private RSA/EC JWK (or JWKS with one private key) for private_key_jwt")
  String clientJwkFile;

  @Option(
      names = "--assertion-alg",
      paramLabel = "ALG",
      description =
          "Client assertion algorithm (private_key_jwt: JWK alg, else RS256 or the curve's ES*;"
              + " client_secret_jwt: HS256)")
  String assertionAlg;

  @Option(
      names = "--assertion-aud",
      paramLabel = "AUD",
      description = "Client assertion audience (default: the endpoint being called)")
  String assertionAud;

  @Option(
      names = "--assertion-lifetime",
      paramLabel = "SECONDS",
      defaultValue = "60",
      description = "Client assertion lifetime in seconds (default: ${DEFAULT-VALUE})")
  long assertionLifetime;

  /** Copy the flags that were set into a params map for {@code OauthSupport}. */
  void applyTo(Map<String, Object> params) {
    if (clientAuth != null && !clientAuth.isBlank()) {
      params.put("clientAuth", clientAuth);
      params.put("assertionLifetimeSeconds", assertionLifetime);
    }
    if (clientJwkFile != null && !clientJwkFile.isBlank()) {
      params.put("clientJwkFile", clientJwkFile);
    }
    if (assertionAlg != null && !assertionAlg.isBlank()) {
      params.put("assertionAlg", assertionAlg);
    }
    if (assertionAud != null && !assertionAud.isBlank()) {
      params.put("assertionAudience", assertionAud);
    }
  }
}
