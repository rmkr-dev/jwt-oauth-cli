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
    name = "device-code",
    description =
        "Start an RFC 8628 device authorization request (POSTs to the device authorization endpoint)")
public class OauthDeviceCodeCommand implements Callable<Integer> {

  @Option(
      names = "--device-authorization-endpoint",
      required = true,
      description = "Device authorization endpoint URL")
  String deviceAuthorizationEndpoint;

  @Option(names = "--client-id", required = true, description = "OAuth client ID")
  String clientId;

  @Option(names = "--scope", description = "Space-separated scopes (optional)")
  String scope;

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
      params.put("deviceAuthorizationEndpoint", deviceAuthorizationEndpoint);
      params.put("clientId", clientId);
      if (scope != null && !scope.isEmpty()) {
        params.put("scope", scope);
      }
      if (secret != null && !secret.isEmpty()) {
        params.put("clientSecret", secret);
      }

      Map<String, Object> result = OauthSupport.deviceAuthorization(params);
      writeJson(System.out, result, compact);
      return 0;
    } catch (Exception e) {
      err.println(e.getMessage());
      return 1;
    }
  }
}
