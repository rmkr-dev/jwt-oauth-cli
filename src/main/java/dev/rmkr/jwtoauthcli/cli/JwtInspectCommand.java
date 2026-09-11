package dev.rmkr.jwtoauthcli.cli;

import dev.rmkr.jwtoauthcli.jwt.JwtSupport;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.io.PrintWriter;
import java.util.Map;
import java.util.concurrent.Callable;

import static dev.rmkr.jwtoauthcli.cli.CliJson.writeJson;

@Command(name = "inspect", description = "Summarize JWT claims including expiration")
public class JwtInspectCommand implements Callable<Integer> {

  @Parameters(index = "0", description = "JWT string")
  String token;

  @Option(
      names = {"-c", "--compact"},
      description = "Print compact single-line JSON")
  boolean compact;

  @Override
  public Integer call() {
    PrintWriter err = new PrintWriter(System.err, true);
    try {
      Map<String, Object> result = JwtSupport.inspect(token);
      writeJson(System.out, result, compact);
      return 0;
    } catch (Exception e) {
      err.println(e.getMessage());
      return 1;
    }
  }
}
