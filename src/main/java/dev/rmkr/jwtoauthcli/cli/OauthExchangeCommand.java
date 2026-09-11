package dev.rmkr.jwtoauthcli.cli;

import dev.rmkr.jwtoauthcli.oauth.OauthSupport;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.io.PrintWriter;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.Callable;

import static dev.rmkr.jwtoauthcli.cli.CliJson.writeJson;

@Command(
    name = "exchange",
    description = "Exchange an authorization code for tokens (POSTs to the token endpoint)")
public class OauthExchangeCommand implements Callable<Integer> {

  @Option(names = "--token-endpoint", required = true, description = "Token endpoint URL")
  String tokenEndpoint;

  @Option(names = "--code", required = true, description = "Authorization code")
  String code;

  @Option(names = "--redirect-uri", required = true, description = "Redirect URI used in authorize")
  String redirectUri;

  @Option(names = "--client-id", required = true, description = "OAuth client ID")
  String clientId;

  @Option(
      names = "--client-secret",
      description =
          "Client secret (sent in POST body only; prefer env JWT_OAUTH_CLIENT_SECRET)")
  String clientSecret;

  @Option(names = "--code-verifier", description = "PKCE code_verifier")
  String codeVerifier;

  @Option(names = "--grant-type", description = "grant_type", defaultValue = "authorization_code")
  String grantType;

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

      Map<String, Object> params = new LinkedHashMap<>();
      params.put("tokenEndpoint", tokenEndpoint);
      params.put("code", code);
      params.put("redirectUri", redirectUri);
      params.put("clientId", clientId);
      if (secret != null && !secret.isEmpty()) {
        params.put("clientSecret", secret);
      }
      if (codeVerifier != null) {
        params.put("codeVerifier", codeVerifier);
      }
      params.put("grantType", grantType);

      Map<String, Object> result = OauthSupport.exchangeCode(params);
      writeJson(System.out, result, compact);
      return 0;
    } catch (Exception e) {
      err.println(e.getMessage());
      return 1;
    }
  }
}
