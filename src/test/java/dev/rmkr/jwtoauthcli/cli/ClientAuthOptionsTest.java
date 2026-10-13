package dev.rmkr.jwtoauthcli.cli;

import org.junit.jupiter.api.Test;
import picocli.CommandLine;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class ClientAuthOptionsTest {

  @Test
  void flagsAreParsedIntoParams() {
    OauthClientCredentialsCommand cmd = new OauthClientCredentialsCommand();
    new CommandLine(cmd)
        .parseArgs(
            "--token-endpoint", "https://auth.example/token",
            "--client-id", "svc",
            "--client-auth", "private_key_jwt",
            "--client-jwk-file", "/keys/client.jwk",
            "--assertion-alg", "PS256",
            "--assertion-aud", "https://auth.example",
            "--assertion-lifetime", "90");

    Map<String, Object> params = new LinkedHashMap<>();
    cmd.clientAuth.applyTo(params);
    assertEquals("private_key_jwt", params.get("clientAuth"));
    assertEquals("/keys/client.jwk", params.get("clientJwkFile"));
    assertEquals("PS256", params.get("assertionAlg"));
    assertEquals("https://auth.example", params.get("assertionAudience"));
    assertEquals(90L, params.get("assertionLifetimeSeconds"));
  }

  @Test
  void noFlagsLeaveParamsUntouched() {
    OauthRevokeCommand cmd = new OauthRevokeCommand();
    new CommandLine(cmd)
        .parseArgs(
            "--revocation-endpoint", "https://auth.example/revoke",
            "--token", "t",
            "--client-id", "c");
    Map<String, Object> params = new LinkedHashMap<>();
    cmd.clientAuth.applyTo(params);
    assertTrue(params.isEmpty());
  }

  @Test
  void everyClientAuthenticatingCommandExposesTheFlags() {
    Object[] commands = {
      new OauthExchangeCommand(),
      new OauthRefreshCommand(),
      new OauthClientCredentialsCommand(),
      new OauthDeviceCodeCommand(),
      new OauthDeviceTokenCommand(),
      new OauthIntrospectCommand(),
      new OauthRevokeCommand()
    };
    for (Object c : commands) {
      CommandLine.Model.CommandSpec spec = new CommandLine(c).getCommandSpec();
      for (String flag :
          new String[] {
            "--client-auth", "--client-jwk-file", "--assertion-alg", "--assertion-aud",
            "--assertion-lifetime"
          }) {
        assertNotNull(spec.findOption(flag), spec.name() + " missing " + flag);
      }
    }
  }
}
