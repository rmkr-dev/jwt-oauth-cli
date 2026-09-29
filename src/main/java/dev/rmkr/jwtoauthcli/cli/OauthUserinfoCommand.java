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
    name = "userinfo",
    description = "Call the OIDC UserInfo endpoint with a bearer access token")
public class OauthUserinfoCommand implements Callable<Integer> {

  @Option(
      names = "--userinfo-endpoint",
      required = true,
      description = "OIDC UserInfo endpoint URL")
  String userinfoEndpoint;

  @Option(
      names = "--access-token",
      description =
          "Access token (Bearer). Prefer env JWT_OAUTH_ACCESS_TOKEN; never logged")
  String accessToken;

  @Option(
      names = {"-c", "--compact"},
      description = "Print compact single-line JSON")
  boolean compact;

  @Override
  public Integer call() {
    PrintWriter err = new PrintWriter(System.err, true);
    try {
      // Prefer env over flag so secrets stay out of process lists / shell history.
      String token =
          OauthSupport.preferEnvOverFlag(System.getenv("JWT_OAUTH_ACCESS_TOKEN"), accessToken);

      Map<String, Object> params = new LinkedHashMap<>();
      params.put("userinfoEndpoint", userinfoEndpoint);
      if (token != null && !token.isEmpty()) {
        params.put("accessToken", token);
      }

      Map<String, Object> result = OauthSupport.userinfo(params);
      writeJson(System.out, result, compact);
      return 0;
    } catch (Exception e) {
      err.println(e.getMessage());
      return 1;
    }
  }
}
