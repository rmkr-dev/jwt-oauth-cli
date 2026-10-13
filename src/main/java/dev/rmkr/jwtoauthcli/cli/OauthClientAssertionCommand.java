package dev.rmkr.jwtoauthcli.cli;

import dev.rmkr.jwtoauthcli.oauth.ClientAssertionSupport;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.io.PrintWriter;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.Callable;

import static dev.rmkr.jwtoauthcli.cli.CliJson.writeJson;

@Command(
    name = "client-assertion",
    description =
        "Print a signed RFC 7523 client assertion (private_key_jwt or client_secret_jwt)"
            + " without calling any endpoint")
public class OauthClientAssertionCommand implements Callable<Integer> {

  @Option(names = "--client-id", required = true, description = "OAuth client ID (iss and sub)")
  String clientId;

  @Option(
      names = "--aud",
      required = true,
      description = "Assertion audience, usually the token endpoint URL")
  String audience;

  @Option(
      names = "--client-auth",
      paramLabel = "METHOD",
      description =
          "private_key_jwt or client_secret_jwt (default: private_key_jwt when --client-jwk-file"
              + " is set, else client_secret_jwt)")
  String clientAuth;

  @Option(
      names = "--client-jwk-file",
      paramLabel = "FILE",
      description = "Private RSA/EC JWK (or JWKS with one private key) for private_key_jwt")
  String clientJwkFile;

  @Option(
      names = "--client-secret",
      description = "Client secret for client_secret_jwt (prefer env JWT_OAUTH_CLIENT_SECRET)")
  String clientSecret;

  @Option(
      names = "--assertion-alg",
      paramLabel = "ALG",
      description =
          "Signing algorithm (private_key_jwt: JWK alg, else RS256 or the curve's ES*;"
              + " client_secret_jwt: HS256)")
  String assertionAlg;

  @Option(
      names = "--assertion-lifetime",
      paramLabel = "SECONDS",
      defaultValue = "60",
      description = "Assertion lifetime in seconds (default: ${DEFAULT-VALUE})")
  long assertionLifetime;

  @Option(
      names = {"-c", "--compact"},
      description = "Print compact single-line JSON")
  boolean compact;

  @Override
  public Integer call() {
    PrintWriter err = new PrintWriter(System.err, true);
    try {
      String secret = clientSecret;
      if (secret == null || secret.isEmpty()) {
        secret = System.getenv("JWT_OAUTH_CLIENT_SECRET");
      }

      Map<String, Object> options = new LinkedHashMap<>();
      options.put("clientId", clientId);
      options.put("audience", audience);
      if (clientAuth != null && !clientAuth.isBlank()) {
        options.put("method", clientAuth);
      }
      if (clientJwkFile != null && !clientJwkFile.isBlank()) {
        options.put("clientJwkFile", clientJwkFile);
      } else if (secret != null && !secret.isEmpty()) {
        options.put("clientSecret", secret);
      }
      if (assertionAlg != null && !assertionAlg.isBlank()) {
        options.put("alg", assertionAlg);
      }
      options.put("lifetimeSeconds", assertionLifetime);

      Map<String, Object> result = ClientAssertionSupport.buildAssertion(options);
      writeJson(System.out, result, compact);
      return 0;
    } catch (Exception e) {
      err.println(e.getMessage());
      return 1;
    }
  }
}
