package dev.rmkr.jwtoauthcli.cli;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.rmkr.jwtoauthcli.jwt.JwtSupport;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;

import static dev.rmkr.jwtoauthcli.cli.CliJson.writeJson;

@Command(
    name = "sign",
    description = "Create an HMAC-signed JWT for local testing (HS256/HS384/HS512)")
public class JwtSignCommand implements Callable<Integer> {

  private static final ObjectMapper MAPPER = new ObjectMapper();

  @Option(
      names = "--secret",
      description =
          "HMAC shared secret for HS256/HS384/HS512 (prefer env JWT_OAUTH_HMAC_SECRET)")
  String secret;

  @Option(
      names = "--alg",
      description = "Signing algorithm: HS256, HS384, or HS512 (default: ${DEFAULT-VALUE})",
      defaultValue = "HS256")
  String alg;

  @Option(names = "--sub", description = "Subject (sub) claim")
  String sub;

  @Option(names = "--iss", description = "Issuer (iss) claim")
  String iss;

  @Option(
      names = "--aud",
      description = "Audience (aud) claim; repeatable or comma-separated",
      split = ",")
  List<String> aud;

  @Option(
      names = "--exp-seconds",
      description = "Token TTL in seconds from now (default: ${DEFAULT-VALUE})",
      defaultValue = "3600")
  long expSeconds;

  @Option(
      names = "--iat",
      description = "Include iat claim set to now (default: ${DEFAULT-VALUE})",
      defaultValue = "true",
      negatable = true)
  boolean iat;

  @Option(
      names = "--nbf-seconds",
      description = "Not-before offset in seconds from now (optional)")
  Long nbfSeconds;

  @Option(names = "--jti", description = "JWT ID (jti) claim")
  String jti;

  @Option(names = "--jti-random", description = "Generate a random jti UUID")
  boolean jtiRandom;

  @Option(names = "--kid", description = "Optional kid header")
  String kid;

  @Option(
      names = "--claim",
      description = "Custom claim KEY=VALUE (repeatable; numbers/bools/JSON parsed when obvious)",
      arity = "1")
  List<String> claims;

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
      options.put("alg", alg);
      if (sub != null && !sub.isEmpty()) {
        options.put("sub", sub);
      }
      if (iss != null && !iss.isEmpty()) {
        options.put("iss", iss);
      }
      if (aud != null && !aud.isEmpty()) {
        List<String> audiences = new ArrayList<>();
        for (String a : aud) {
          if (a != null) {
            String t = a.trim();
            if (!t.isEmpty()) {
              audiences.add(t);
            }
          }
        }
        if (!audiences.isEmpty()) {
          options.put("aud", audiences);
        }
      }
      options.put("expSeconds", expSeconds);
      options.put("iat", iat);
      if (nbfSeconds != null) {
        options.put("nbfSeconds", nbfSeconds);
      }
      if (jti != null && !jti.isEmpty()) {
        options.put("jti", jti);
      }
      if (jtiRandom) {
        options.put("jtiRandom", true);
      }
      if (kid != null && !kid.isEmpty()) {
        options.put("kid", kid);
      }
      if (claims != null && !claims.isEmpty()) {
        Map<String, Object> custom = new LinkedHashMap<>();
        for (String raw : claims) {
          int eq = raw.indexOf('=');
          if (eq <= 0) {
            throw new IllegalArgumentException(
                "Invalid --claim '" + raw + "'; expected KEY=VALUE");
          }
          String key = raw.substring(0, eq).trim();
          String value = raw.substring(eq + 1);
          custom.put(key, parseClaimValue(value));
        }
        options.put("claims", custom);
      }

      Map<String, Object> result = JwtSupport.sign(options);
      writeJson(System.out, result, compact);
      return 0;
    } catch (Exception e) {
      err.println(e.getMessage());
      return 1;
    }
  }

  static Object parseClaimValue(String value) {
    if (value == null) {
      return null;
    }
    String trimmed = value.trim();
    if ("true".equalsIgnoreCase(trimmed)) {
      return true;
    }
    if ("false".equalsIgnoreCase(trimmed)) {
      return false;
    }
    if ("null".equalsIgnoreCase(trimmed)) {
      return null;
    }
    if ((trimmed.startsWith("{") && trimmed.endsWith("}"))
        || (trimmed.startsWith("[") && trimmed.endsWith("]"))) {
      try {
        return MAPPER.readValue(trimmed, Object.class);
      } catch (Exception ignored) {
        // fall through to string / number
      }
    }
    try {
      if (trimmed.matches("-?\\d+")) {
        return Long.parseLong(trimmed);
      }
      if (trimmed.matches("-?\\d+\\.\\d+([eE][-+]?\\d+)?")) {
        return Double.parseDouble(trimmed);
      }
    } catch (NumberFormatException ignored) {
      // fall through
    }
    return value;
  }
}
