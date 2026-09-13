package dev.rmkr.jwtoauthcli.cli;

import dev.rmkr.jwtoauthcli.jwt.JwtSupport;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.io.PrintWriter;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.Callable;

import static dev.rmkr.jwtoauthcli.cli.CliJson.writeJson;

@Command(
    name = "verify",
    description =
        "Verify a JWT signature (HMAC secret or JWKS) with optional claim checks")
public class JwtVerifyCommand implements Callable<Integer> {

  @Parameters(index = "0", description = "JWT string")
  String token;

  @Option(
      names = "--secret",
      description =
          "HMAC shared secret for HS256/HS384/HS512 (prefer env JWT_OAUTH_HMAC_SECRET)")
  String secret;

  @Option(names = "--jwks-url", description = "JWKS URL for RS/ES verification by kid/alg")
  String jwksUrl;

  @Option(names = "--iss", description = "Expected issuer (iss) claim")
  String iss;

  @Option(names = "--aud", description = "Expected audience (aud) claim")
  String aud;

  @Option(
      names = "--exp-leeway-seconds",
      description = "Clock skew leeway for exp claim (default: ${DEFAULT-VALUE})",
      defaultValue = "60")
  long expLeewaySeconds;

  @Option(
      names = {"-c", "--compact"},
      description = "Print compact single-line JSON")
  boolean compact;

  @Override
  public Integer call() {
    PrintWriter err = new PrintWriter(System.err, true);
    try {
      String hmac = secret;
      if (hmac == null || hmac.isEmpty()) {
        hmac = System.getenv("JWT_OAUTH_HMAC_SECRET");
      }

      Map<String, Object> options = new LinkedHashMap<>();
      if (hmac != null && !hmac.isEmpty()) {
        options.put("secret", hmac);
      }
      if (jwksUrl != null && !jwksUrl.isEmpty()) {
        options.put("jwksUrl", jwksUrl);
      }
      if (iss != null && !iss.isEmpty()) {
        options.put("iss", iss);
      }
      if (aud != null && !aud.isEmpty()) {
        options.put("aud", aud);
      }
      options.put("expLeewaySeconds", expLeewaySeconds);

      Map<String, Object> result = JwtSupport.verify(token, options);
      writeJson(System.out, result, compact);
      return 0;
    } catch (Exception e) {
      err.println(e.getMessage());
      return 1;
    }
  }
}
