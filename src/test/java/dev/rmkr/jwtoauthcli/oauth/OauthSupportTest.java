package dev.rmkr.jwtoauthcli.oauth;

import dev.rmkr.jwtoauthcli.http.FormPoster;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class OauthSupportTest {

  @Test
  void buildsStandardAuthorizationUrl() throws Exception {
    Map<String, Object> params = new LinkedHashMap<>();
    params.put("authorizationEndpoint", "https://auth.example/authorize");
    params.put("clientId", "my-client");
    params.put("redirectUri", "http://127.0.0.1:8080/callback");
    params.put("scope", "openid profile");
    params.put("state", "xyz");

    String url = OauthSupport.buildAuthorizeUrl(params);
    java.net.URI parsed = java.net.URI.create(url);
    assertEquals("https://auth.example/authorize", parsed.getScheme() + "://" + parsed.getHost() + parsed.getPath());

    Map<String, String> q = query(parsed);
    assertEquals("code", q.get("response_type"));
    assertEquals("my-client", q.get("client_id"));
    assertEquals("http://127.0.0.1:8080/callback", q.get("redirect_uri"));
    assertEquals("openid profile", q.get("scope"));
    assertEquals("xyz", q.get("state"));
  }

  @Test
  void joinsArrayScopesAndSupportsPkce() {
    Map<String, Object> params = new LinkedHashMap<>();
    params.put("authorizationEndpoint", "https://auth.example/oauth/authorize");
    params.put("clientId", "c");
    params.put("redirectUri", "http://localhost/cb");
    params.put("scope", List.of("openid", "email"));
    params.put("codeChallenge", "challenge-value");

    String url = OauthSupport.buildAuthorizeUrl(params);
    Map<String, String> q = query(java.net.URI.create(url));
    assertEquals("openid email", q.get("scope"));
    assertEquals("challenge-value", q.get("code_challenge"));
    assertEquals("S256", q.get("code_challenge_method"));
  }

  @Test
  void requiresCoreParametersForAuthorizeUrl() {
    Map<String, Object> params = new LinkedHashMap<>();
    params.put("clientId", "c");
    params.put("redirectUri", "http://localhost/cb");
    IllegalArgumentException ex =
        assertThrows(IllegalArgumentException.class, () -> OauthSupport.buildAuthorizeUrl(params));
    assertTrue(ex.getMessage().contains("authorizationEndpoint"));
  }

  @Test
  void exchangePostsFormBodyAndReturnsJson() throws Exception {
    List<Captured> calls = new ArrayList<>();
    FormPoster poster =
        (url, formBody, headers) -> {
          calls.add(new Captured(url, formBody, headers));
          return new FormPoster.HttpResponse(
              200,
              true,
              "{\"access_token\":\"atok\",\"token_type\":\"Bearer\",\"expires_in\":3600}");
        };

    Map<String, Object> params = new LinkedHashMap<>();
    params.put("tokenEndpoint", "https://auth.example/token");
    params.put("code", "auth-code");
    params.put("redirectUri", "http://127.0.0.1:8080/callback");
    params.put("clientId", "my-client");
    params.put("clientSecret", "s3cret");
    params.put("codeVerifier", "verifier");

    Map<String, Object> result = OauthSupport.exchangeCode(params, poster);
    assertEquals("atok", result.get("access_token"));
    assertEquals(1, calls.size());
    assertEquals("https://auth.example/token", calls.get(0).url);
    assertTrue(calls.get(0).headers.get("content-type").contains("application/x-www-form-urlencoded"));

    Map<String, String> body = form(calls.get(0).formBody);
    assertEquals("authorization_code", body.get("grant_type"));
    assertEquals("auth-code", body.get("code"));
    assertEquals("my-client", body.get("client_id"));
    assertEquals("s3cret", body.get("client_secret"));
    assertEquals("verifier", body.get("code_verifier"));
  }

  @Test
  void exchangeSurfacesTokenEndpointErrors() {
    FormPoster poster =
        (url, formBody, headers) ->
            new FormPoster.HttpResponse(
                400,
                false,
                "{\"error\":\"invalid_grant\",\"error_description\":\"code expired\"}");

    Map<String, Object> params = new LinkedHashMap<>();
    params.put("tokenEndpoint", "https://auth.example/token");
    params.put("code", "bad");
    params.put("redirectUri", "http://127.0.0.1/cb");
    params.put("clientId", "c");

    Exception ex =
        assertThrows(Exception.class, () -> OauthSupport.exchangeCode(params, poster));
    assertTrue(ex.getMessage().contains("code expired"));
  }

  @Test
  void generatePkceReturnsValidS256Pair() throws Exception {
    Map<String, Object> pair = OauthSupport.generatePkce();
    String verifier = (String) pair.get("code_verifier");
    String challenge = (String) pair.get("code_challenge");
    assertEquals("S256", pair.get("code_challenge_method"));
    assertNotNull(pair.get("state"));
    assertTrue(verifier.length() >= 43 && verifier.length() <= 128);
    assertTrue(verifier.matches("[A-Za-z0-9\\-._~]+"));
    assertTrue(((String) pair.get("state")).matches("[A-Za-z0-9\\-_]+"));

    byte[] digest =
        MessageDigest.getInstance("SHA-256")
            .digest(verifier.getBytes(StandardCharsets.US_ASCII));
    String expected =
        java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    assertEquals(expected, challenge);
  }

  @Test
  void generatePkceProducesUniqueValues() {
    Map<String, Object> a = OauthSupport.generatePkce();
    Map<String, Object> b = OauthSupport.generatePkce();
    assertNotEquals(a.get("code_verifier"), b.get("code_verifier"));
    assertNotEquals(a.get("state"), b.get("state"));
  }

  @Test
  void generatePkceRejectsInvalidVerifierBytes() {
    IllegalArgumentException ex =
        assertThrows(IllegalArgumentException.class, () -> OauthSupport.generatePkce(8));
    assertTrue(ex.getMessage().contains("verifierBytes"));
  }

  @Test
  void refreshPostsFormBodyAndReturnsJson() throws Exception {
    List<Captured> calls = new ArrayList<>();
    FormPoster poster =
        (url, formBody, headers) -> {
          calls.add(new Captured(url, formBody, headers));
          return new FormPoster.HttpResponse(
              200,
              true,
              "{\"access_token\":\"new-atok\",\"token_type\":\"Bearer\",\"expires_in\":3600,\"refresh_token\":\"new-rtok\"}");
        };

    Map<String, Object> params = new LinkedHashMap<>();
    params.put("tokenEndpoint", "https://auth.example/token");
    params.put("refreshToken", "old-rtok");
    params.put("clientId", "my-client");
    params.put("clientSecret", "s3cret");
    params.put("scope", "openid profile");

    Map<String, Object> result = OauthSupport.refreshToken(params, poster);
    assertEquals("new-atok", result.get("access_token"));
    assertEquals(1, calls.size());
    assertEquals("https://auth.example/token", calls.get(0).url);
    assertTrue(calls.get(0).headers.get("content-type").contains("application/x-www-form-urlencoded"));

    Map<String, String> body = form(calls.get(0).formBody);
    assertEquals("refresh_token", body.get("grant_type"));
    assertEquals("old-rtok", body.get("refresh_token"));
    assertEquals("my-client", body.get("client_id"));
    assertEquals("s3cret", body.get("client_secret"));
    assertEquals("openid profile", body.get("scope"));
  }

  @Test
  void refreshSurfacesErrors() {
    FormPoster poster =
        (url, formBody, headers) ->
            new FormPoster.HttpResponse(
                400,
                false,
                "{\"error\":\"invalid_grant\",\"error_description\":\"refresh token revoked\"}");

    Map<String, Object> params = new LinkedHashMap<>();
    params.put("tokenEndpoint", "https://auth.example/token");
    params.put("refreshToken", "bad");
    params.put("clientId", "c");

    Exception ex =
        assertThrows(Exception.class, () -> OauthSupport.refreshToken(params, poster));
    assertTrue(ex.getMessage().contains("refresh token revoked"));
  }

  @Test
  void refreshRequiresCoreParameters() {
    Map<String, Object> params = new LinkedHashMap<>();
    params.put("tokenEndpoint", "https://auth.example/token");
    params.put("clientId", "c");
    Exception ex =
        assertThrows(Exception.class, () -> OauthSupport.refreshToken(params));
    assertTrue(ex.getMessage().contains("refreshToken"));
  }

  private record Captured(String url, String formBody, Map<String, String> headers) {}

  private static Map<String, String> query(java.net.URI uri) {
    Map<String, String> map = new LinkedHashMap<>();
    String raw = uri.getRawQuery();
    if (raw == null) {
      return map;
    }
    for (String pair : raw.split("&")) {
      int eq = pair.indexOf('=');
      if (eq < 0) {
        map.put(java.net.URLDecoder.decode(pair, StandardCharsets.UTF_8), "");
      } else {
        map.put(
            java.net.URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8),
            java.net.URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8));
      }
    }
    return map;
  }

  private static Map<String, String> form(String body) {
    Map<String, String> map = new LinkedHashMap<>();
    for (String pair : body.split("&")) {
      int eq = pair.indexOf('=');
      map.put(
          java.net.URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8),
          java.net.URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8));
    }
    return map;
  }
}
