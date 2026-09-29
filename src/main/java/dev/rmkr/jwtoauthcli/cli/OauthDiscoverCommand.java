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
    name = "discover",
    description =
        "Fetch OpenID Provider / OAuth Authorization Server metadata (OIDC discovery with OAuth AS fallback)")
public class OauthDiscoverCommand implements Callable<Integer> {

  @Option(
      names = "--issuer",
      description =
          "Issuer base URL (appends /.well-known/openid-configuration; falls back to oauth-authorization-server)")
  String issuer;

  @Option(
      names = "--metadata-url",
      description = "Direct metadata document URL (skips issuer well-known resolution)")
  String metadataUrl;

  @Option(
      names = {"-c", "--compact"},
      description = "Print compact single-line JSON")
  boolean compact;

  @Override
  public Integer call() {
    PrintWriter err = new PrintWriter(System.err, true);
    try {
      Map<String, Object> params = new LinkedHashMap<>();
      if (issuer != null && !issuer.isEmpty()) {
        params.put("issuer", issuer);
      }
      if (metadataUrl != null && !metadataUrl.isEmpty()) {
        params.put("metadataUrl", metadataUrl);
      }
      Map<String, Object> result = OauthSupport.discover(params);
      writeJson(System.out, result, compact);
      return 0;
    } catch (Exception e) {
      err.println(e.getMessage());
      return 1;
    }
  }
}
