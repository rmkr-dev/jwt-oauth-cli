package dev.rmkr.jwtoauthcli.cli;

import dev.rmkr.jwtoauthcli.oauth.OauthSupport;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.io.PrintWriter;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.Callable;

@Command(name = "authorize-url", description = "Build an OAuth 2.0 authorization URL")
public class OauthAuthorizeUrlCommand implements Callable<Integer> {

  @Option(names = "--authorization-endpoint", required = true, description = "Authorization endpoint URL")
  String authorizationEndpoint;

  @Option(names = "--client-id", required = true, description = "OAuth client ID")
  String clientId;

  @Option(names = "--redirect-uri", required = true, description = "Redirect URI")
  String redirectUri;

  @Option(names = "--response-type", description = "response_type", defaultValue = "code")
  String responseType;

  @Option(names = "--scope", description = "Space-separated scopes")
  String scope;

  @Option(names = "--state", description = "Opaque state value")
  String state;

  @Option(names = "--code-challenge", description = "PKCE code_challenge")
  String codeChallenge;

  @Option(
      names = "--code-challenge-method",
      description = "PKCE code_challenge_method",
      defaultValue = "S256")
  String codeChallengeMethod;

  @Override
  public Integer call() {
    PrintWriter err = new PrintWriter(System.err, true);
    try {
      Map<String, Object> params = new LinkedHashMap<>();
      params.put("authorizationEndpoint", authorizationEndpoint);
      params.put("clientId", clientId);
      params.put("redirectUri", redirectUri);
      params.put("responseType", responseType);
      if (scope != null) {
        params.put("scope", scope);
      }
      if (state != null) {
        params.put("state", state);
      }
      if (codeChallenge != null) {
        params.put("codeChallenge", codeChallenge);
        params.put("codeChallengeMethod", codeChallengeMethod);
      }
      String url = OauthSupport.buildAuthorizeUrl(params);
      System.out.println(url);
      return 0;
    } catch (Exception e) {
      err.println(e.getMessage());
      return 1;
    }
  }
}
