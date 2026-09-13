package dev.rmkr.jwtoauthcli.cli;

import picocli.CommandLine.Command;

@Command(
    name = "oauth",
    description = "OAuth 2.0 utilities",
    subcommands = {
      OauthAuthorizeUrlCommand.class,
      OauthPkceCommand.class,
      OauthExchangeCommand.class,
      OauthRefreshCommand.class,
      OauthClientCredentialsCommand.class
    })
public class OauthCommands implements Runnable {
  @Override
  public void run() {
    new picocli.CommandLine(this).usage(System.out);
  }
}
