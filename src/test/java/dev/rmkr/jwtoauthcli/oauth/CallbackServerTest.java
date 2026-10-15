package dev.rmkr.jwtoauthcli.oauth;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

/** Runs the real listener on an ephemeral loopback port. */
@Timeout(value = 20, unit = TimeUnit.SECONDS)
class CallbackServerTest {

  private final HttpClient client =
      HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
  private final ExecutorService pool = Executors.newSingleThreadExecutor();

  @AfterEach
  void shutdown() {
    pool.shutdownNow();
  }

  private record Running(Future<CallbackSupport.Result> result, int port) {}

  private Running start(CallbackSupport.Options options) throws Exception {
    CompletableFuture<Integer> port = new CompletableFuture<>();
    options.onListening(addr -> port.complete(addr.getPort()));
    Future<CallbackSupport.Result> result = pool.submit(() -> CallbackSupport.await(options));
    try {
      return new Running(result, port.get(10, TimeUnit.SECONDS));
    } catch (Exception e) {
      if (result.isDone()) {
        result.get();
      }
      throw e;
    }
  }

  private HttpResponse<String> get(int port, String pathAndQuery) throws Exception {
    HttpRequest req =
        HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + pathAndQuery))
            .timeout(Duration.ofSeconds(5))
            .GET()
            .build();
    return client.send(req, HttpResponse.BodyHandlers.ofString());
  }

  @Test
  void catchesAuthorizationCodeAndAnswersTheBrowser() throws Exception {
    Running r =
        start(
            new CallbackSupport.Options("http://127.0.0.1:0/callback")
                .expectedState("xyz")
                .timeout(Duration.ofSeconds(10)));

    HttpResponse<String> notFound = get(r.port(), "/favicon.ico");
    assertEquals(404, notFound.statusCode());

    HttpResponse<String> missing = get(r.port(), "/callback");
    assertEquals(400, missing.statusCode());

    HttpResponse<String> ok =
        get(r.port(), "/callback?code=abc%2B1&state=xyz&iss=https%3A%2F%2Fauth.example");
    assertEquals(200, ok.statusCode());
    assertTrue(ok.headers().firstValue("Content-Type").orElse("").startsWith("text/html"));
    assertEquals("no-store", ok.headers().firstValue("Cache-Control").orElse(""));
    assertTrue(ok.body().contains("You can close this window"));
    assertFalse(ok.body().contains("abc+1"));

    CallbackSupport.Result result = r.result().get(5, TimeUnit.SECONDS);
    assertEquals(CallbackSupport.Outcome.CODE, result.outcome());
    assertEquals("abc+1", result.fields().get("code"));
    assertEquals("xyz", result.fields().get("state"));
    assertEquals("https://auth.example", result.fields().get("iss"));
  }

  @Test
  void stopsListeningAfterTheRedirect() throws Exception {
    Running r = start(new CallbackSupport.Options("http://127.0.0.1:0/"));
    assertEquals(200, get(r.port(), "/?code=one").statusCode());
    r.result().get(5, TimeUnit.SECONDS);
    assertThrows(IOException.class, () -> get(r.port(), "/?code=two"));
  }

  @Test
  void errorRedirectUsesCustomErrorPage() throws Exception {
    Running r =
        start(
            new CallbackSupport.Options("http://127.0.0.1:0/cb")
                .errorHtml("<p>custom failure</p>"));
    HttpResponse<String> resp =
        get(r.port(), "/cb?error=access_denied&error_description=User+cancelled");
    assertEquals(200, resp.statusCode());
    assertEquals("<p>custom failure</p>", resp.body());

    CallbackSupport.Result result = r.result().get(5, TimeUnit.SECONDS);
    assertEquals(CallbackSupport.Outcome.ERROR, result.outcome());
    assertEquals("access_denied", result.fields().get("error"));
    assertEquals("User cancelled", result.fields().get("error_description"));
  }

  @Test
  void customSuccessPageIsServed() throws Exception {
    Running r =
        start(new CallbackSupport.Options("http://127.0.0.1:0/cb").successHtml("<p>done</p>"));
    assertEquals("<p>done</p>", get(r.port(), "/cb?code=c").body());
    assertTrue(r.result().get(5, TimeUnit.SECONDS).isSuccess());
  }

  @Test
  void stateMismatchEndsTheWaitWithAnErrorPage() throws Exception {
    Running r = start(new CallbackSupport.Options("http://127.0.0.1:0/cb").expectedState("good"));
    HttpResponse<String> resp = get(r.port(), "/cb?code=c&state=bad");
    assertEquals(200, resp.statusCode());
    assertTrue(resp.body().contains("state_mismatch"));
    assertFalse(resp.body().contains("code=c"));

    CallbackSupport.Result result = r.result().get(5, TimeUnit.SECONDS);
    assertEquals(CallbackSupport.Outcome.STATE_MISMATCH, result.outcome());
    assertFalse(result.fields().containsKey("code"));
  }

  @Test
  void nonGetRequestsAreRejectedWithoutEndingTheWait() throws Exception {
    Running r = start(new CallbackSupport.Options("http://127.0.0.1:0/cb"));
    HttpRequest post =
        HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + r.port() + "/cb?code=c"))
            .POST(HttpRequest.BodyPublishers.noBody())
            .build();
    HttpResponse<String> resp = client.send(post, HttpResponse.BodyHandlers.ofString());
    assertEquals(405, resp.statusCode());
    assertEquals("GET", resp.headers().firstValue("Allow").orElse(""));
    assertFalse(r.result().isDone());

    assertEquals(200, get(r.port(), "/cb?code=c").statusCode());
    assertTrue(r.result().get(5, TimeUnit.SECONDS).isSuccess());
  }

  @Test
  void timesOutWhenNothingArrives() throws Exception {
    Running r =
        start(
            new CallbackSupport.Options("http://127.0.0.1:0/cb")
                .timeout(Duration.ofMillis(300)));
    assertEquals(404, get(r.port(), "/other").statusCode());
    CallbackSupport.Result result = r.result().get(5, TimeUnit.SECONDS);
    assertEquals(CallbackSupport.Outcome.TIMEOUT, result.outcome());
    assertTrue(result.message().startsWith("Timed out after 300ms"));
    assertTrue(result.message().contains("1 request was ignored"));
    assertTrue(result.fields().isEmpty());
  }

  @Test
  void givesUpAfterTooManyIgnoredRequests() throws Exception {
    Running r =
        start(new CallbackSupport.Options("http://127.0.0.1:0/cb").maxIgnoredRequests(3));
    get(r.port(), "/a");
    get(r.port(), "/b");
    get(r.port(), "/cb?state=only");
    CallbackSupport.Result result = r.result().get(5, TimeUnit.SECONDS);
    assertEquals(CallbackSupport.Outcome.TOO_MANY_IGNORED, result.outcome());
    assertTrue(result.message().startsWith("Gave up after 3 requests"));
  }

  @Test
  void bindOverrideIsUsedInsteadOfTheRedirectHost() throws Exception {
    // The redirect host does not resolve, so this only works if --bind is honoured.
    Running r =
        start(new CallbackSupport.Options("http://callback.invalid:0/cb").bind("127.0.0.1"));
    assertEquals(200, get(r.port(), "/cb?code=c").statusCode());
    assertTrue(r.result().get(5, TimeUnit.SECONDS).isSuccess());
  }

  @Test
  void localhostBindsTheLoopbackAddress() throws Exception {
    Running r = start(new CallbackSupport.Options("http://localhost:0/cb"));
    HttpRequest req =
        HttpRequest.newBuilder(
                URI.create(
                    "http://"
                        + InetAddress.getLoopbackAddress().getHostAddress().replaceAll("^(.*:.*)$", "[$1]")
                        + ":"
                        + r.port()
                        + "/cb?code=c"))
            .GET()
            .build();
    assertEquals(200, client.send(req, HttpResponse.BodyHandlers.ofString()).statusCode());
    assertTrue(r.result().get(5, TimeUnit.SECONDS).isSuccess());
  }

  @Test
  void reportsBindFailureClearly() throws Exception {
    try (ServerSocket taken = new ServerSocket(0, 50, InetAddress.getLoopbackAddress())) {
      int port = taken.getLocalPort();
      IOException e =
          assertThrows(
              IOException.class,
              () ->
                  CallbackSupport.await(
                      new CallbackSupport.Options("http://127.0.0.1:" + port + "/cb")
                          .timeout(Duration.ofSeconds(1))));
      assertTrue(e.getMessage().startsWith("Could not listen on 127.0.0.1:" + port), e.getMessage());
    }
  }

  @Test
  void rejectsInvalidSettingsBeforeBinding() {
    assertThrows(
        IllegalArgumentException.class,
        () ->
            CallbackSupport.await(
                new CallbackSupport.Options("http://127.0.0.1:0/cb").timeout(Duration.ZERO)));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            CallbackSupport.await(
                new CallbackSupport.Options("http://127.0.0.1:0/cb").maxIgnoredRequests(0)));
    assertThrows(
        IllegalArgumentException.class,
        () -> CallbackSupport.await(new CallbackSupport.Options("https://127.0.0.1:0/cb")));
  }
}
