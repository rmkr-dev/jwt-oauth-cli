package dev.rmkr.jwtoauthcli.cli;

import picocli.CommandLine.Command;

@Command(
    name = "jwt",
    description = "JWT utilities",
    subcommands = {
      JwtDecodeCommand.class,
      JwtInspectCommand.class,
      JwtVerifyCommand.class,
      JwtSignCommand.class
    })
public class JwtCommands implements Runnable {
  @Override
  public void run() {
    new picocli.CommandLine(this).usage(System.out);
  }
}
