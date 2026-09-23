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
    name = "introspect",
    description =
        "Introspect a token at an RFC 7662 introspection endpoint (POSTs form body)")
public class OauthIntrospectCommand implements Callable<Integer> {

  @Option(
      names = "--introspection-endpoint",
      required = true,
      description = "Token introspection endpoint URL")
  String introspectionEndpoint;

  @Option(names = "--token", required = true, description = "Access or refresh token to introspect")
  String token;

  @Option(
      names = "--token-type-hint",
      description = "Optional hint: access_token or refresh_token")
  String tokenTypeHint;

  @Option(names = "--client-id", required = true, description = "OAuth client ID")
  String clientId;

  @Option(
      names = "--client-secret",
      description =
          "Client secret (sent in POST body only; prefer env JWT_OAUTH_CLIENT_SECRET)")
  String clientSecret;

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
      params.put("introspectionEndpoint", introspectionEndpoint);
      params.put("token", token);
      params.put("clientId", clientId);
      if (secret != null && !secret.isEmpty()) {
        params.put("clientSecret", secret);
      }
      if (tokenTypeHint != null && !tokenTypeHint.isEmpty()) {
        params.put("tokenTypeHint", tokenTypeHint);
      }

      Map<String, Object> result = OauthSupport.introspect(params);
      writeJson(System.out, result, compact);
      return 0;
    } catch (Exception e) {
      err.println(e.getMessage());
      return 1;
    }
  }
}
