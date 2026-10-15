package dev.rmkr.jwtoauthcli.oauth;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class CallbackSupportTest {

  @Test
  void parsesHostPortAndPathFromRedirectUri() {
    CallbackSupport.Endpoint e =
        CallbackSupport.parseRedirectUri("http://127.0.0.1:8765/callback");
    assertEquals("127.0.0.1", e.host());
    assertEquals(8765, e.port());
    assertEquals("/callback", e.path());
  }

  @Test
  void redirectUriDefaultsToRootPathAndPort80() {
    CallbackSupport.Endpoint e = CallbackSupport.parseRedirectUri("http://localhost");
    assertEquals("localhost", e.host());
    assertEquals(80, e.port());
    assertEquals("/", e.path());

    assertEquals("/", CallbackSupport.parseRedirectUri("http://127.0.0.1:9000").path());
  }

  @Test
  void redirectUriKeepsIpv6LiteralAndIgnoresQuery() {
    CallbackSupport.Endpoint e =
        CallbackSupport.parseRedirectUri("http://[::1]:8765/cb?tenant=dev");
    assertEquals("[::1]", e.host());
    assertEquals(8765, e.port());
    assertEquals("/cb", e.path());
  }

  @Test
  void rejectsUnusableRedirectUris() {
    assertThrows(IllegalArgumentException.class, () -> CallbackSupport.parseRedirectUri(null));
    assertThrows(IllegalArgumentException.class, () -> CallbackSupport.parseRedirectUri(" "));
    assertThrows(
        IllegalArgumentException.class, () -> CallbackSupport.parseRedirectUri("/callback"));
    assertThrows(
        IllegalArgumentException.class, () -> CallbackSupport.parseRedirectUri("http://"));
    assertThrows(
        IllegalArgumentException.class,
        () -> CallbackSupport.parseRedirectUri("http://127.0.0.1:8765/cb#frag"));
    IllegalArgumentException https =
        assertThrows(
            IllegalArgumentException.class,
            () -> CallbackSupport.parseRedirectUri("https://127.0.0.1:8765/cb"));
    assertTrue(https.getMessage().contains("http"));
    assertThrows(
        IllegalArgumentException.class,
        () -> CallbackSupport.parseRedirectUri("http://127.0.0.1:87 65/cb"));
  }

  @Test
  void parsesQueryWithDecodingAndFirstValueWins() {
    Map<String, String> q =
        CallbackSupport.parseQuery("code=abc%2F123&state=s+1&state=other&flag&&empty=");
    assertEquals("abc/123", q.get("code"));
    assertEquals("s 1", q.get("state"));
    assertEquals("", q.get("flag"));
    assertEquals("", q.get("empty"));
    assertEquals(4, q.size());
  }

  @Test
  void emptyQueryGivesEmptyMap() {
    assertTrue(CallbackSupport.parseQuery(null).isEmpty());
    assertTrue(CallbackSupport.parseQuery("").isEmpty());
  }

  @Test
  void malformedPercentEncodingIsRejected() {
    assertThrows(IllegalArgumentException.class, () -> CallbackSupport.parseQuery("code=%zz"));
  }

  @Test
  void pathMatchingIsExact() {
    assertTrue(CallbackSupport.pathMatches("/callback", "/callback"));
    assertTrue(CallbackSupport.pathMatches("/", ""));
    assertTrue(CallbackSupport.pathMatches("", "/"));
    assertFalse(CallbackSupport.pathMatches("/callback", "/callback/"));
    assertFalse(CallbackSupport.pathMatches("/callback", "/callbackx"));
    assertFalse(CallbackSupport.pathMatches("/callback", "/favicon.ico"));
  }

  @Test
  void codeRedirectKeepsOnlyKnownFields() {
    Map<String, String> q = new LinkedHashMap<>();
    q.put("code", "abc");
    q.put("state", "xyz");
    q.put("iss", "https://auth.example");
    q.put("scope", "openid profile");
    q.put("session_state", "ss");
    q.put("authuser", "0");

    CallbackSupport.Result r = CallbackSupport.evaluate(q, null);
    assertEquals(CallbackSupport.Outcome.CODE, r.outcome());
    assertTrue(r.isSuccess());
    assertEquals(
        Map.of(
            "code", "abc",
            "state", "xyz",
            "iss", "https://auth.example",
            "scope", "openid profile",
            "session_state", "ss"),
        r.fields());
    assertFalse(r.fields().containsKey("authuser"));
  }

  @Test
  void codeWithoutStateIsFineWhenNoStateIsExpected() {
    CallbackSupport.Result r = CallbackSupport.evaluate(Map.of("code", "abc"), null);
    assertEquals(CallbackSupport.Outcome.CODE, r.outcome());
    assertEquals(Map.of("code", "abc"), r.fields());
  }

  @Test
  void matchingExpectedStateIsAccepted() {
    CallbackSupport.Result r =
        CallbackSupport.evaluate(Map.of("code", "abc", "state", "xyz"), "xyz");
    assertEquals(CallbackSupport.Outcome.CODE, r.outcome());
  }

  @Test
  void differentStateIsRejectedAndCodeIsDropped() {
    CallbackSupport.Result r =
        CallbackSupport.evaluate(Map.of("code", "abc", "state", "evil"), "xyz");
    assertEquals(CallbackSupport.Outcome.STATE_MISMATCH, r.outcome());
    assertFalse(r.isSuccess());
    assertEquals("state_mismatch", r.fields().get("error"));
    assertEquals("evil", r.fields().get("state"));
    assertFalse(r.fields().containsKey("code"));
    assertTrue(r.message().contains("did not match"));
  }

  @Test
  void missingStateIsRejectedWhenExpected() {
    CallbackSupport.Result r = CallbackSupport.evaluate(Map.of("code", "abc"), "xyz");
    assertEquals(CallbackSupport.Outcome.STATE_MISMATCH, r.outcome());
    assertFalse(r.fields().containsKey("state"));
    assertTrue(r.message().contains("did not include state"));
  }

  @Test
  void errorRedirectReportsErrorFields() {
    Map<String, String> q = new LinkedHashMap<>();
    q.put("error", "access_denied");
    q.put("error_description", "User cancelled");
    q.put("error_uri", "https://auth.example/errors/access_denied");
    q.put("state", "xyz");
    q.put("code", "should-not-matter");

    CallbackSupport.Result r = CallbackSupport.evaluate(q, "xyz");
    assertEquals(CallbackSupport.Outcome.ERROR, r.outcome());
    assertEquals("access_denied", r.fields().get("error"));
    assertEquals("User cancelled", r.fields().get("error_description"));
    assertEquals("https://auth.example/errors/access_denied", r.fields().get("error_uri"));
    assertEquals("xyz", r.fields().get("state"));
    assertFalse(r.fields().containsKey("code"));
    assertEquals(
        "Authorization server returned error: access_denied (User cancelled)", r.message());
  }

  @Test
  void errorRedirectWithWrongStateIsAStateMismatch() {
    CallbackSupport.Result r =
        CallbackSupport.evaluate(Map.of("error", "access_denied", "state", "evil"), "xyz");
    assertEquals(CallbackSupport.Outcome.STATE_MISMATCH, r.outcome());
  }

  @Test
  void redirectWithoutCodeOrErrorIsIgnored() {
    assertEquals(
        CallbackSupport.Outcome.IGNORED,
        CallbackSupport.evaluate(Map.of("state", "xyz"), "xyz").outcome());
    assertEquals(
        CallbackSupport.Outcome.IGNORED,
        CallbackSupport.evaluate(Map.of("code", ""), null).outcome());
    assertEquals(CallbackSupport.Outcome.IGNORED, CallbackSupport.evaluate(null, null).outcome());
  }

  @Test
  void stateComparisonHandlesNullAndUnicode() {
    assertTrue(CallbackSupport.stateMatches("é-1", "é-1"));
    assertFalse(CallbackSupport.stateMatches("abc", null));
    assertFalse(CallbackSupport.stateMatches("abc", "abcd"));
  }

  @Test
  void defaultSuccessPageSaysTheWindowCanBeClosed() {
    String html = CallbackSupport.successHtml(null);
    assertTrue(html.startsWith("<!doctype html>"));
    assertTrue(html.contains("You can close this window"));
    assertEquals("<p>ok</p>", CallbackSupport.successHtml("<p>ok</p>"));
    assertTrue(CallbackSupport.successHtml("").contains("You can close this window"));
  }

  @Test
  void defaultErrorPageEscapesServerSuppliedText() {
    String html = CallbackSupport.errorHtml(null, "access_denied", "<script>alert(1)</script>");
    assertTrue(html.contains("You can close this window"));
    assertTrue(html.contains("access_denied"));
    assertTrue(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
    assertFalse(html.contains("<script>"));
    assertEquals("<p>nope</p>", CallbackSupport.errorHtml("<p>nope</p>", "x", "y"));
  }

  @Test
  void escapesAllHtmlSpecialCharacters() {
    assertEquals("&amp;&lt;&gt;&quot;&#39;a", CallbackSupport.escapeHtml("&<>\"'a"));
  }

  @Test
  void timeoutMessageNamesUriDurationAndIgnoredRequests() {
    assertEquals(
        "Timed out after 300s waiting for a redirect to http://127.0.0.1:8765/callback",
        CallbackSupport.timeoutMessage(
            "http://127.0.0.1:8765/callback", Duration.ofSeconds(300), 0));
    String withIgnored =
        CallbackSupport.timeoutMessage("http://127.0.0.1:1/cb", Duration.ofMillis(250), 2);
    assertTrue(withIgnored.startsWith("Timed out after 250ms"));
    assertTrue(withIgnored.contains("2 requests were ignored"));
    assertTrue(
        CallbackSupport.timeoutMessage("http://127.0.0.1:1/cb", Duration.ofSeconds(1), 1)
            .contains("1 request was ignored"));
  }

  @Test
  void tooManyIgnoredMessageNamesTheUri() {
    String msg = CallbackSupport.tooManyIgnoredMessage("http://127.0.0.1:1/cb", 50);
    assertTrue(msg.startsWith("Gave up after 50 requests"));
    assertTrue(msg.contains("http://127.0.0.1:1/cb"));
  }
}
