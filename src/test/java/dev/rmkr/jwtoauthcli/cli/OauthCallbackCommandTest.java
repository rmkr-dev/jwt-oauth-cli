package dev.rmkr.jwtoauthcli.cli;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import picocli.CommandLine;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

@Timeout(value = 20, unit = TimeUnit.SECONDS)
class OauthCallbackCommandTest {

  private static final ObjectMapper MAPPER = new ObjectMapper();

  private static final class Run {
    final OauthCallbackCommand cmd = new OauthCallbackCommand();
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final ByteArrayOutputStream err = new ByteArrayOutputStream();

    Run() {
      cmd.out = new PrintStream(out, true, StandardCharsets.UTF_8);
      cmd.errStream = new PrintStream(err, true, StandardCharsets.UTF_8);
    }

    CompletableFuture<Integer> execute(String... args) {
      return CompletableFuture.supplyAsync(() -> new CommandLine(cmd).execute(args));
    }

    String stdout() {
      return out.toString(StandardCharsets.UTF_8);
    }

    String stderr() {
      return err.toString(StandardCharsets.UTF_8);
    }
  }

  @Test
  void isRegisteredUnderOauth() {
    CommandLine oauth = new CommandLine(new OauthCommands());
    assertTrue(oauth.getSubcommands().containsKey("callback"));
  }

  @Test
  void defaultsMatchTheDocumentation() {
    OauthCallbackCommand cmd = new OauthCallbackCommand();
    new CommandLine(cmd).parseArgs("--redirect-uri", "http://127.0.0.1:8765/callback");
    assertEquals(300, cmd.timeoutSeconds);
    assertNull(cmd.bind);
    assertNull(cmd.expectedState);
    assertFalse(cmd.compact);
  }

  @Test
  void redirectUriIsRequired() {
    Run run = new Run();
    CommandLine cl = new CommandLine(run.cmd);
    cl.setErr(new java.io.PrintWriter(new java.io.StringWriter()));
    assertEquals(2, cl.execute());
  }

  @Test
  void printsCodeAsJsonAndExitsZero() throws Exception {
    int port = freePort();
    Run run = new Run();
    CompletableFuture<Integer> exit =
        run.execute(
            "--redirect-uri", "http://127.0.0.1:" + port + "/callback",
            "--expected-state", "xyz",
            "--timeout-seconds", "10",
            "--compact");

    HttpResponse<String> resp = getWhenListening(port, "/callback?code=abc&state=xyz");
    assertEquals(200, resp.statusCode());
    assertEquals(0, exit.get(10, TimeUnit.SECONDS));

    String stdout = run.stdout();
    assertEquals(1, stdout.trim().lines().count(), "compact output is one line");
    assertEquals(Map.of("code", "abc", "state", "xyz"), MAPPER.readValue(stdout, Map.class));
    assertTrue(run.stderr().contains("Waiting for redirect on http://127.0.0.1:" + port + "/callback"));
  }

  @Test
  void printsErrorJsonAndExitsOne() throws Exception {
    int port = freePort();
    Run run = new Run();
    CompletableFuture<Integer> exit =
        run.execute("--redirect-uri", "http://127.0.0.1:" + port, "--timeout-seconds", "10");

    getWhenListening(port, "/?error=access_denied&state=s");
    assertEquals(1, exit.get(10, TimeUnit.SECONDS));
    assertEquals(
        Map.of("error", "access_denied", "state", "s"), MAPPER.readValue(run.stdout(), Map.class));
    assertTrue(run.stderr().contains("Authorization server returned error: access_denied"));
  }

  @Test
  void timeoutExitsOneWithAMessage() throws Exception {
    Run run = new Run();
    int code =
        run.execute("--redirect-uri", "http://127.0.0.1:0/cb", "--timeout-seconds", "1")
            .get(10, TimeUnit.SECONDS);
    assertEquals(1, code);
    assertEquals("", run.stdout());
    assertTrue(run.stderr().contains("Timed out after 1s waiting for a redirect"));
  }

  @Test
  void invalidInputExitsOne() throws Exception {
    Run https = new Run();
    assertEquals(1, https.execute("--redirect-uri", "https://127.0.0.1:8765/cb").get());
    assertTrue(https.stderr().contains("must use http"));

    Run zero = new Run();
    assertEquals(
        1,
        zero.execute("--redirect-uri", "http://127.0.0.1:0/cb", "--timeout-seconds", "0").get());
    assertTrue(zero.stderr().contains("--timeout-seconds must be greater than 0"));
  }

  private static int freePort() throws IOException {
    try (ServerSocket s = new ServerSocket(0, 50, InetAddress.getLoopbackAddress())) {
      return s.getLocalPort();
    }
  }

  private static HttpResponse<String> getWhenListening(int port, String pathAndQuery)
      throws Exception {
    HttpClient client = HttpClient.newHttpClient();
    HttpRequest req =
        HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + pathAndQuery))
            .timeout(Duration.ofSeconds(5))
            .GET()
            .build();
    IOException last = null;
    for (int i = 0; i < 100; i++) {
      try {
        return client.send(req, HttpResponse.BodyHandlers.ofString());
      } catch (IOException e) {
        last = e;
        Thread.sleep(50);
      }
    }
    throw last;
  }
}
