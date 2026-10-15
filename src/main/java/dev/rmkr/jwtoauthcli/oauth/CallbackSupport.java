package dev.rmkr.jwtoauthcli.oauth;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.BindException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

/**
 * One-shot loopback listener for the OAuth 2.0 authorization code redirect
 * (RFC 6749 section 4.1.2, RFC 8252 section 7.3).
 *
 * <p>The parsing and validation helpers ({@link #parseRedirectUri},
 * {@link #parseQuery}, {@link #evaluate}) are pure and need no server. {@link
 * #await(Options)} binds a JDK {@link HttpServer}, waits for the first GET on the
 * redirect path that carries {@code code} or {@code error}, answers the browser
 * with an HTML page, and stops.
 *
 * <p>Requests to any other path get 404, requests on the path without
 * {@code code} or {@code error} get 400, and non-GET methods get 405. None of
 * these end the wait, but after {@link Options#maxIgnoredRequests} of them the
 * listener gives up.
 */
public final class CallbackSupport {

  public static final long DEFAULT_TIMEOUT_SECONDS = 300;
  public static final int DEFAULT_MAX_IGNORED_REQUESTS = 50;

  /** Query parameters copied to the result for a successful redirect. */
  static final String[] SUCCESS_KEYS = {"code", "state", "iss", "scope", "session_state"};

  /** Query parameters copied to the result for an error redirect. */
  static final String[] ERROR_KEYS = {"error", "error_description", "error_uri", "state", "iss"};

  private CallbackSupport() {}

  /** What happened to the one-shot wait. */
  public enum Outcome {
    /** The redirect carried an authorization code (and a matching state, if one was expected). */
    CODE,
    /** The authorization server redirected with {@code error}. */
    ERROR,
    /** {@code state} was missing or did not match the expected value. */
    STATE_MISMATCH,
    /** The redirect path was hit but carried neither {@code code} nor {@code error}. */
    IGNORED,
    /** No usable redirect arrived before the timeout. */
    TIMEOUT,
    /** Too many requests that did not count as the redirect. */
    TOO_MANY_IGNORED
  }

  /** Result of {@link #evaluate} or {@link #await}. {@code fields} is what the CLI prints. */
  public record Result(Outcome outcome, Map<String, Object> fields, String message) {
    public Result {
      fields = Collections.unmodifiableMap(new LinkedHashMap<>(fields));
    }

    public boolean isSuccess() {
      return outcome == Outcome.CODE;
    }
  }

  /** Where to listen, derived from a redirect URI. */
  public record Endpoint(String host, int port, String path) {}

  /** Settings for {@link #await(Options)}. */
  public static final class Options {
    private final String redirectUri;
    private String bind;
    private Duration timeout = Duration.ofSeconds(DEFAULT_TIMEOUT_SECONDS);
    private String expectedState;
    private String successHtml;
    private String errorHtml;
    private int maxIgnoredRequests = DEFAULT_MAX_IGNORED_REQUESTS;
    private Consumer<InetSocketAddress> onListening = addr -> {};

    public Options(String redirectUri) {
      this.redirectUri = Objects.requireNonNull(redirectUri, "redirectUri");
    }

    /** Listen address override; defaults to the redirect URI host. */
    public Options bind(String bind) {
      this.bind = bind;
      return this;
    }

    public Options timeout(Duration timeout) {
      this.timeout = Objects.requireNonNull(timeout, "timeout");
      return this;
    }

    public Options expectedState(String expectedState) {
      this.expectedState = expectedState;
      return this;
    }

    public Options successHtml(String successHtml) {
      this.successHtml = successHtml;
      return this;
    }

    public Options errorHtml(String errorHtml) {
      this.errorHtml = errorHtml;
      return this;
    }

    public Options maxIgnoredRequests(int maxIgnoredRequests) {
      this.maxIgnoredRequests = maxIgnoredRequests;
      return this;
    }

    /** Called once the server is accepting connections, with the bound address. */
    public Options onListening(Consumer<InetSocketAddress> onListening) {
      this.onListening = Objects.requireNonNull(onListening, "onListening");
      return this;
    }
  }

  /**
   * Parses a loopback redirect URI into host, port, and path. Only {@code http}
   * is accepted because the listener does not terminate TLS. A missing port
   * means 80 and a missing path means {@code /}.
   */
  public static Endpoint parseRedirectUri(String redirectUri) {
    if (redirectUri == null || redirectUri.isBlank()) {
      throw new IllegalArgumentException("redirect-uri is required");
    }
    URI uri;
    try {
      uri = new URI(redirectUri.trim());
    } catch (URISyntaxException e) {
      throw new IllegalArgumentException("redirect-uri is not a valid URI: " + e.getMessage(), e);
    }
    String scheme = uri.getScheme();
    if (scheme == null || uri.getHost() == null) {
      throw new IllegalArgumentException(
          "redirect-uri must be an absolute URL such as http://127.0.0.1:8765/callback");
    }
    if (!"http".equalsIgnoreCase(scheme)) {
      throw new IllegalArgumentException(
          "redirect-uri must use http; the local listener does not serve " + scheme);
    }
    if (uri.getFragment() != null) {
      throw new IllegalArgumentException("redirect-uri must not contain a fragment");
    }
    int port = uri.getPort() == -1 ? 80 : uri.getPort();
    String path = uri.getRawPath();
    if (path == null || path.isEmpty()) {
      path = "/";
    }
    return new Endpoint(uri.getHost(), port, path);
  }

  /**
   * Decodes an {@code application/x-www-form-urlencoded} query string. The first
   * occurrence of a name wins, a name without {@code =} maps to an empty string,
   * and a null or empty query gives an empty map.
   *
   * @throws IllegalArgumentException on malformed percent-encoding
   */
  public static Map<String, String> parseQuery(String rawQuery) {
    Map<String, String> out = new LinkedHashMap<>();
    if (rawQuery == null || rawQuery.isEmpty()) {
      return out;
    }
    for (String pair : rawQuery.split("&")) {
      if (pair.isEmpty()) {
        continue;
      }
      int eq = pair.indexOf('=');
      String name = eq >= 0 ? pair.substring(0, eq) : pair;
      String value = eq >= 0 ? pair.substring(eq + 1) : "";
      out.putIfAbsent(decode(name), decode(value));
    }
    return out;
  }

  /** True when the request path is exactly the redirect path. */
  public static boolean pathMatches(String expectedPath, String requestPath) {
    String expected = expectedPath == null || expectedPath.isEmpty() ? "/" : expectedPath;
    String actual = requestPath == null || requestPath.isEmpty() ? "/" : requestPath;
    return expected.equals(actual);
  }

  /**
   * Classifies decoded redirect query parameters. When {@code expectedState} is
   * set, a missing or different {@code state} yields {@link Outcome#STATE_MISMATCH}
   * and the code is not returned.
   */
  public static Result evaluate(Map<String, String> query, String expectedState) {
    Map<String, String> q = query == null ? Map.of() : query;
    boolean hasCode = notEmpty(q.get("code"));
    boolean hasError = notEmpty(q.get("error"));
    if (!hasCode && !hasError) {
      return new Result(
          Outcome.IGNORED, Map.of(), "Redirect carried neither code nor error");
    }

    if (expectedState != null && !stateMatches(expectedState, q.get("state"))) {
      Map<String, Object> fields = new LinkedHashMap<>();
      fields.put("error", "state_mismatch");
      fields.put(
          "error_description",
          q.get("state") == null
              ? "Redirect did not include state but --expected-state was set"
              : "Redirect state did not match --expected-state");
      if (q.get("state") != null) {
        fields.put("state", q.get("state"));
      }
      return new Result(
          Outcome.STATE_MISMATCH, fields, (String) fields.get("error_description"));
    }

    if (hasError) {
      Map<String, Object> fields = copy(q, ERROR_KEYS);
      String message = "Authorization server returned error: " + q.get("error");
      if (notEmpty(q.get("error_description"))) {
        message += " (" + q.get("error_description") + ")";
      }
      return new Result(Outcome.ERROR, fields, message);
    }

    return new Result(Outcome.CODE, copy(q, SUCCESS_KEYS), "Authorization code received");
  }

  /** Constant-time state comparison. */
  static boolean stateMatches(String expected, String actual) {
    if (actual == null) {
      return false;
    }
    return MessageDigest.isEqual(
        expected.getBytes(StandardCharsets.UTF_8), actual.getBytes(StandardCharsets.UTF_8));
  }

  /** Browser page for a successful redirect; {@code custom} wins when set. */
  public static String successHtml(String custom) {
    if (notEmpty(custom)) {
      return custom;
    }
    return page(
        "Authorization complete",
        "<p>The authorization code was received. You can close this window and return to the terminal.</p>");
  }

  /**
   * Browser page for an error or rejected redirect; {@code custom} wins when set.
   * The default shows the escaped error code and description, never a code or token.
   */
  public static String errorHtml(String custom, String error, String description) {
    if (notEmpty(custom)) {
      return custom;
    }
    StringBuilder body = new StringBuilder();
    if (notEmpty(error)) {
      body.append("<p><code>").append(escapeHtml(error)).append("</code></p>");
    }
    if (notEmpty(description)) {
      body.append("<p>").append(escapeHtml(description)).append("</p>");
    }
    body.append("<p>You can close this window and check the terminal for details.</p>");
    return page("Authorization failed", body.toString());
  }

  public static String timeoutMessage(String redirectUri, Duration timeout, int ignored) {
    StringBuilder sb =
        new StringBuilder("Timed out after ")
            .append(formatDuration(timeout))
            .append(" waiting for a redirect to ")
            .append(redirectUri);
    if (ignored > 0) {
      sb.append(" (")
          .append(ignored)
          .append(ignored == 1 ? " request was" : " requests were")
          .append(" ignored: wrong path, wrong method, or no code/error)");
    }
    return sb.toString();
  }

  public static String tooManyIgnoredMessage(String redirectUri, int ignored) {
    return "Gave up after "
        + ignored
        + " requests that did not match a redirect to "
        + redirectUri
        + " (wrong path, wrong method, or no code/error)";
  }

  /**
   * Binds the listener, waits for one redirect, answers the browser, and stops.
   *
   * @throws IOException when the address cannot be bound
   */
  public static Result await(Options options) throws IOException, InterruptedException {
    Endpoint endpoint = parseRedirectUri(options.redirectUri);
    if (options.timeout.isZero() || options.timeout.isNegative()) {
      throw new IllegalArgumentException("timeout-seconds must be greater than 0");
    }
    if (options.maxIgnoredRequests < 1) {
      throw new IllegalArgumentException("maxIgnoredRequests must be at least 1");
    }

    String bindHost = notEmpty(options.bind) ? options.bind.trim() : endpoint.host();
    InetSocketAddress address = new InetSocketAddress(resolve(bindHost), endpoint.port());

    HttpServer server;
    try {
      server = HttpServer.create(address, 0);
    } catch (BindException e) {
      throw new IOException(
          "Could not listen on " + describe(address) + ": " + e.getMessage(), e);
    }

    CountDownLatch done = new CountDownLatch(1);
    AtomicReference<Result> result = new AtomicReference<>();
    AtomicInteger ignored = new AtomicInteger();

    server.createContext(
        "/",
        exchange -> {
          try {
            handle(exchange, endpoint, options, result, ignored, done);
          } finally {
            exchange.close();
          }
        });

    ExecutorService executor =
        Executors.newSingleThreadExecutor(
            r -> {
              Thread t = new Thread(r, "oauth-callback");
              t.setDaemon(true);
              return t;
            });
    server.setExecutor(executor);
    server.start();
    try {
      options.onListening.accept(server.getAddress());
      String shownUri = displayUri(endpoint, server.getAddress().getPort());
      boolean finished = done.await(options.timeout.toMillis(), TimeUnit.MILLISECONDS);
      Result r = result.get();
      if (!finished || r == null) {
        return new Result(
            Outcome.TIMEOUT, Map.of(), timeoutMessage(shownUri, options.timeout, ignored.get()));
      }
      if (r.outcome() == Outcome.TOO_MANY_IGNORED) {
        return new Result(
            Outcome.TOO_MANY_IGNORED, Map.of(), tooManyIgnoredMessage(shownUri, ignored.get()));
      }
      return r;
    } finally {
      server.stop(0);
      executor.shutdownNow();
    }
  }

  private static void handle(
      HttpExchange exchange,
      Endpoint endpoint,
      Options options,
      AtomicReference<Result> result,
      AtomicInteger ignored,
      CountDownLatch done)
      throws IOException {
    if (result.get() != null) {
      respond(exchange, 410, page("Already handled", "<p>This listener has already finished.</p>"));
      return;
    }
    if (!pathMatches(endpoint.path(), exchange.getRequestURI().getRawPath())) {
      respond(exchange, 404, page("Not found", "<p>Not found.</p>"));
      countIgnored(ignored, options, result, done);
      return;
    }
    if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
      exchange.getResponseHeaders().set("Allow", "GET");
      respond(exchange, 405, page("Method not allowed", "<p>Only GET is accepted.</p>"));
      countIgnored(ignored, options, result, done);
      return;
    }

    Result r;
    try {
      r = evaluate(parseQuery(exchange.getRequestURI().getRawQuery()), options.expectedState);
    } catch (IllegalArgumentException e) {
      respond(exchange, 400, errorHtml(null, "invalid_request", "Malformed query string"));
      countIgnored(ignored, options, result, done);
      return;
    }
    if (r.outcome() == Outcome.IGNORED) {
      respond(exchange, 400, errorHtml(null, "invalid_request", r.message()));
      countIgnored(ignored, options, result, done);
      return;
    }

    String html =
        r.isSuccess()
            ? successHtml(options.successHtml)
            : errorHtml(
                options.errorHtml,
                (String) r.fields().get("error"),
                (String) r.fields().get("error_description"));
    try {
      respond(exchange, 200, html);
    } finally {
      if (result.compareAndSet(null, r)) {
        done.countDown();
      }
    }
  }

  private static void countIgnored(
      AtomicInteger ignored,
      Options options,
      AtomicReference<Result> result,
      CountDownLatch done) {
    if (ignored.incrementAndGet() >= options.maxIgnoredRequests
        && result.compareAndSet(null, new Result(Outcome.TOO_MANY_IGNORED, Map.of(), ""))) {
      done.countDown();
    }
  }

  private static void respond(HttpExchange exchange, int status, String html) throws IOException {
    byte[] body = html.getBytes(StandardCharsets.UTF_8);
    exchange.getResponseHeaders().set("Content-Type", "text/html; charset=utf-8");
    exchange.getResponseHeaders().set("Cache-Control", "no-store");
    exchange.getResponseHeaders().set("Referrer-Policy", "no-referrer");
    boolean head = "HEAD".equalsIgnoreCase(exchange.getRequestMethod());
    exchange.sendResponseHeaders(status, head ? -1 : body.length);
    if (!head) {
      try (OutputStream os = exchange.getResponseBody()) {
        os.write(body);
      }
    }
  }

  private static InetAddress resolve(String host) throws UnknownHostException {
    String h = host;
    if (h.startsWith("[") && h.endsWith("]")) {
      h = h.substring(1, h.length() - 1);
    }
    if ("localhost".equalsIgnoreCase(h)) {
      return InetAddress.getLoopbackAddress();
    }
    return InetAddress.getByName(h);
  }

  private static String describe(InetSocketAddress address) {
    String host = address.getAddress() != null ? address.getAddress().getHostAddress() : address.getHostString();
    if (host.contains(":")) {
      host = "[" + host + "]";
    }
    return host + ":" + address.getPort();
  }

  static String displayUri(Endpoint endpoint, int port) {
    String host = endpoint.host();
    return "http://" + host + ":" + port + endpoint.path();
  }

  private static String page(String title, String bodyHtml) {
    return "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
        + "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        + "<title>"
        + escapeHtml(title)
        + "</title></head><body style=\"font-family: system-ui, sans-serif; max-width: 36rem; margin: 3rem auto; padding: 0 1rem;\">"
        + "<h1>"
        + escapeHtml(title)
        + "</h1>"
        + bodyHtml
        + "</body></html>\n";
  }

  static String escapeHtml(String s) {
    StringBuilder sb = new StringBuilder(s.length());
    for (int i = 0; i < s.length(); i++) {
      char c = s.charAt(i);
      switch (c) {
        case '&' -> sb.append("&amp;");
        case '<' -> sb.append("&lt;");
        case '>' -> sb.append("&gt;");
        case '"' -> sb.append("&quot;");
        case '\'' -> sb.append("&#39;");
        default -> sb.append(c);
      }
    }
    return sb.toString();
  }

  private static String formatDuration(Duration d) {
    long millis = d.toMillis();
    if (millis % 1000 == 0) {
      return (millis / 1000) + "s";
    }
    return millis + "ms";
  }

  private static Map<String, Object> copy(Map<String, String> q, String[] keys) {
    Map<String, Object> out = new LinkedHashMap<>();
    for (String k : keys) {
      String v = q.get(k);
      if (v != null) {
        out.put(k, v);
      }
    }
    return out;
  }

  private static boolean notEmpty(String s) {
    return s != null && !s.isEmpty();
  }

  private static String decode(String s) {
    return URLDecoder.decode(s, StandardCharsets.UTF_8);
  }
}
