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
    name = "device-token",
    description =
        "Request tokens with an RFC 8628 device code (POSTs to the token endpoint)")
public class OauthDeviceTokenCommand implements Callable<Integer> {

  @Option(names = "--token-endpoint", required = true, description = "Token endpoint URL")
  String tokenEndpoint;

  @Option(names = "--device-code", required = true, description = "Device code from device-code")
  String deviceCode;

  @Option(names = "--client-id", required = true, description = "OAuth client ID")
  String clientId;

  @Option(
      names = "--client-secret",
      description =
          "Client secret (sent in POST body only; prefer env JWT_OAUTH_CLIENT_SECRET)")
  String clientSecret;

  @Option(
      names = "--wait",
      description =
          "Poll until a token is issued, a terminal error occurs, or max wait elapses")
  boolean waitForToken;

  @Option(
      names = "--interval",
      defaultValue = "5",
      description =
          "Seconds between polls when --wait is set (default: 5; slow_down adds 5 unless the response includes interval)")
  int interval;

  @Option(
      names = "--max-wait-seconds",
      defaultValue = "600",
      description = "Give up after this many seconds when --wait is set (default: 600)")
  int maxWaitSeconds;

  @Option(
      names = {"-c", "--compact"},
      description = "Print compact single-line JSON")
  boolean compact;

  @Override
  public Integer call() {
    PrintWriter err = new PrintWriter(System.err, true);
    try {
      String secret = clientSecret;
      if (secret == null || secret.isEmpty()) {
        secret = System.getenv("JWT_OAUTH_CLIENT_SECRET");
      }

      Map<String, Object> params = new LinkedHashMap<>();
      params.put("tokenEndpoint", tokenEndpoint);
      params.put("deviceCode", deviceCode);
      params.put("clientId", clientId);
      if (secret != null && !secret.isEmpty()) {
        params.put("clientSecret", secret);
      }

      int sleepSeconds = interval > 0 ? interval : 5;
      long deadlineNanos = System.nanoTime() + Math.max(0, maxWaitSeconds) * 1_000_000_000L;

      while (true) {
        Map<String, Object> result = OauthSupport.deviceToken(params);
        if (result.get("access_token") != null) {
          writeJson(System.out, result, compact);
          return 0;
        }

        String error = result.get("error") == null ? "" : String.valueOf(result.get("error"));
        boolean stillPending =
            "authorization_pending".equals(error) || "slow_down".equals(error);
        if (!stillPending) {
          err.println(error.isEmpty() ? "Device token request failed" : error);
          return 1;
        }
        if (!waitForToken) {
          writeJson(System.out, result, compact);
          return 2;
        }

        if ("slow_down".equals(error)) {
          sleepSeconds = nextPollInterval(sleepSeconds, result);
        }

        long now = System.nanoTime();
        if (now >= deadlineNanos) {
          err.println(
              "Timed out waiting for device authorization after " + maxWaitSeconds + " seconds");
          return 1;
        }
        long remainingMs = (deadlineNanos - now) / 1_000_000L;
        long sleepMs = sleepSeconds * 1000L;
        if (sleepMs > remainingMs) {
          err.println(
              "Timed out waiting for device authorization after " + maxWaitSeconds + " seconds");
          return 1;
        }
        Thread.sleep(sleepMs);
      }
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      err.println("Interrupted while waiting for device authorization");
      return 1;
    } catch (Exception e) {
      err.println(e.getMessage());
      return 1;
    }
  }

  /**
   * Prefer a positive {@code interval} from a slow_down response. Otherwise add
   * {@code interval_increase} (default 5) to the current poll interval.
   */
  private static int nextPollInterval(int current, Map<String, Object> result) {
    Object hinted = result.get("interval");
    if (hinted instanceof Number n && n.intValue() > 0) {
      return n.intValue();
    }
    int bump = 5;
    Object increase = result.get("interval_increase");
    if (increase instanceof Number n && n.intValue() > 0) {
      bump = n.intValue();
    }
    long next = (long) current + bump;
    if (next > Integer.MAX_VALUE) {
      return Integer.MAX_VALUE;
    }
    return (int) next;
  }
}
