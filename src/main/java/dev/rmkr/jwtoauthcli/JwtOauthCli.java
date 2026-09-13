package dev.rmkr.jwtoauthcli;

import dev.rmkr.jwtoauthcli.cli.JwtCommands;
import dev.rmkr.jwtoauthcli.cli.OauthCommands;
import picocli.CommandLine;
import picocli.CommandLine.Command;

@Command(
    name = "jwt-oauth-cli",
    mixinStandardHelpOptions = true,
    version = "0.3.0",
    description =
        "Decode/inspect/verify JWTs and run local OAuth helpers (authorize URL, PKCE, code exchange, refresh, client-credentials)",
    subcommands = {JwtCommands.class, OauthCommands.class})
public final class JwtOauthCli implements Runnable {

  @Override
  public void run() {
    CommandLine.usage(this, System.out);
  }

  public static void main(String[] args) {
    int code =
        new CommandLine(new JwtOauthCli())
            .setExecutionExceptionHandler(
                (ex, commandLine, parseResult) -> {
                  String msg = ex.getMessage() != null ? ex.getMessage() : String.valueOf(ex);
                  commandLine.getErr().println(msg);
                  return commandLine.getCommandSpec().exitCodeOnExecutionException();
                })
            .execute(args);
    System.exit(code);
  }
}
