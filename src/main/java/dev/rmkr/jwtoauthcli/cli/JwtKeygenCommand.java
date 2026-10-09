package dev.rmkr.jwtoauthcli.cli;

import dev.rmkr.jwtoauthcli.jwt.KeyGenSupport;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.io.PrintWriter;
import java.util.Map;
import java.util.concurrent.Callable;

import static dev.rmkr.jwtoauthcli.cli.CliJson.writeJson;

@Command(
    name = "keygen",
    description = "Generate a signing key as a JWK (plus public JWK and JWKS for RSA/EC)")
public class JwtKeygenCommand implements Callable<Integer> {

  @Option(
      names = {"-a", "--alg"},
      defaultValue = "RS256",
      description = "JWS algorithm: RS*/PS*/ES*/HS* 256|384|512 (default: ${DEFAULT-VALUE})")
  String alg;

  @Option(names = "--kid", description = "Key id (default: RFC 7638 thumbprint)")
  String kid;

  @Option(
      names = "--rsa-bits",
      defaultValue = "2048",
      description = "RSA key size in bits (default: ${DEFAULT-VALUE})")
  int rsaBits;

  @Option(
      names = "--public-only",
      description = "Print only the public JWKS (RSA/EC only)")
  boolean publicOnly;

  @Option(
      names = {"-c", "--compact"},
      description = "Print compact single-line JSON")
  boolean compact;

  @Override
  public Integer call() {
    PrintWriter err = new PrintWriter(System.err, true);
    try {
      Map<String, Object> result = KeyGenSupport.generate(alg, kid, rsaBits);
      if (publicOnly) {
        Object jwks = result.get("jwks");
        if (jwks == null) {
          err.println("--public-only requires an asymmetric alg (RS*, PS*, ES*)");
          return 2;
        }
        writeJson(System.out, jwks, compact);
      } else {
        writeJson(System.out, result, compact);
      }
      return 0;
    } catch (Exception e) {
      err.println(e.getMessage());
      return 1;
    }
  }
}
