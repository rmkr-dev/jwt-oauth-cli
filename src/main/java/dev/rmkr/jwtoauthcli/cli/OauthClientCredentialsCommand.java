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
    name = "client-credentials",
    description =
        "Request tokens using the client_credentials grant (POSTs to the token endpoint)")
public class OauthClientCredentialsCommand implements Callable<Integer> {

  @Option(names = "--token-endpoint", required = true, description = "Token endpoint URL")
  String tokenEndpoint;

  @Option(names = "--client-id", required = true, description = "OAuth client ID")
  String clientId;

  @Option(
      names = "--client-secret",
      description =
          "Client secret (sent in POST body only; prefer env JWT_OAUTH_CLIENT_SECRET)")
  String clientSecret;

  @Option(names = "--scope", description = "Space-separated scopes (optional)")
  String scope;

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
      if (secret == null || secret.isEmpty()) {
        err.println(
            "clientSecret is required (pass --client-secret or set JWT_OAUTH_CLIENT_SECRET)");
        return 1;
      }

      Map<String, Object> params = new LinkedHashMap<>();
      params.put("tokenEndpoint", tokenEndpoint);
      params.put("clientId", clientId);
      params.put("clientSecret", secret);
      if (scope != null) {
        params.put("scope", scope);
      }

      Map<String, Object> result = OauthSupport.clientCredentials(params);
      writeJson(System.out, result, compact);
      return 0;
    } catch (Exception e) {
      err.println(e.getMessage());
      return 1;
    }
  }
}
