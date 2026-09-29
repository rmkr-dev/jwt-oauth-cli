package dev.rmkr.jwtoauthcli.oauth;

import dev.rmkr.jwtoauthcli.http.FormPoster;
import dev.rmkr.jwtoauthcli.http.JsonGetClient;
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


  @Test
  void clientCredentialsPostsFormBodyAndReturnsJson() throws Exception {
    List<Captured> calls = new ArrayList<>();
    FormPoster poster =
        (url, formBody, headers) -> {
          calls.add(new Captured(url, formBody, headers));
          return new FormPoster.HttpResponse(
              200,
              true,
              "{\"access_token\":\"cc-atok\",\"token_type\":\"Bearer\",\"expires_in\":3600}");
        };

    Map<String, Object> params = new LinkedHashMap<>();
    params.put("tokenEndpoint", "https://auth.example/token");
    params.put("clientId", "my-client");
    params.put("clientSecret", "s3cret");
    params.put("scope", "api.read");

    Map<String, Object> result = OauthSupport.clientCredentials(params, poster);
    assertEquals("cc-atok", result.get("access_token"));
    assertEquals(1, calls.size());
    assertEquals("https://auth.example/token", calls.get(0).url);
    assertTrue(calls.get(0).headers.get("content-type").contains("application/x-www-form-urlencoded"));

    Map<String, String> body = form(calls.get(0).formBody);
    assertEquals("client_credentials", body.get("grant_type"));
    assertEquals("my-client", body.get("client_id"));
    assertEquals("s3cret", body.get("client_secret"));
    assertEquals("api.read", body.get("scope"));
  }

  @Test
  void clientCredentialsSurfacesErrors() {
    FormPoster poster =
        (url, formBody, headers) ->
            new FormPoster.HttpResponse(
                401,
                false,
                "{\"error\":\"invalid_client\",\"error_description\":\"bad credentials\"}");

    Map<String, Object> params = new LinkedHashMap<>();
    params.put("tokenEndpoint", "https://auth.example/token");
    params.put("clientId", "c");
    params.put("clientSecret", "bad");

    Exception ex =
        assertThrows(Exception.class, () -> OauthSupport.clientCredentials(params, poster));
    assertTrue(ex.getMessage().contains("bad credentials"));
  }

  @Test
  void clientCredentialsRequiresClientSecret() {
    Map<String, Object> params = new LinkedHashMap<>();
    params.put("tokenEndpoint", "https://auth.example/token");
    params.put("clientId", "c");
    Exception ex =
        assertThrows(Exception.class, () -> OauthSupport.clientCredentials(params));
    assertTrue(ex.getMessage().contains("clientSecret"));
  }

  @Test
  void introspectPostsFormBodyAndReturnsJson() throws Exception {
    List<Captured> calls = new ArrayList<>();
    FormPoster poster =
        (url, formBody, headers) -> {
          calls.add(new Captured(url, formBody, headers));
          return new FormPoster.HttpResponse(
              200,
              true,
              "{\"active\":true,\"scope\":\"openid\",\"client_id\":\"my-client\",\"username\":\"alice\"}");
        };

    Map<String, Object> params = new LinkedHashMap<>();
    params.put("introspectionEndpoint", "https://auth.example/introspect");
    params.put("token", "access-tok");
    params.put("clientId", "my-client");
    params.put("clientSecret", "s3cret");
    params.put("tokenTypeHint", "access_token");

    Map<String, Object> result = OauthSupport.introspect(params, poster);
    assertEquals(true, result.get("active"));
    assertEquals("alice", result.get("username"));
    assertEquals(1, calls.size());
    assertEquals("https://auth.example/introspect", calls.get(0).url);
    assertTrue(calls.get(0).headers.get("content-type").contains("application/x-www-form-urlencoded"));

    Map<String, String> body = form(calls.get(0).formBody);
    assertEquals("access-tok", body.get("token"));
    assertEquals("my-client", body.get("client_id"));
    assertEquals("s3cret", body.get("client_secret"));
    assertEquals("access_token", body.get("token_type_hint"));
  }

  @Test
  void introspectSurfacesErrors() {
    FormPoster poster =
        (url, formBody, headers) ->
            new FormPoster.HttpResponse(
                401,
                false,
                "{\"error\":\"invalid_client\",\"error_description\":\"bad credentials\"}");

    Map<String, Object> params = new LinkedHashMap<>();
    params.put("introspectionEndpoint", "https://auth.example/introspect");
    params.put("token", "tok");
    params.put("clientId", "c");
    params.put("clientSecret", "bad");

    Exception ex =
        assertThrows(Exception.class, () -> OauthSupport.introspect(params, poster));
    assertTrue(ex.getMessage().contains("bad credentials"));
  }

  @Test
  void introspectRequiresToken() {
    Map<String, Object> params = new LinkedHashMap<>();
    params.put("introspectionEndpoint", "https://auth.example/introspect");
    params.put("clientId", "c");
    Exception ex = assertThrows(Exception.class, () -> OauthSupport.introspect(params));
    assertTrue(ex.getMessage().contains("token"));
  }

  @Test
  void revokeTreats200AsSuccess() throws Exception {
    List<Captured> calls = new ArrayList<>();
    FormPoster poster =
        (url, formBody, headers) -> {
          calls.add(new Captured(url, formBody, headers));
          return new FormPoster.HttpResponse(200, true, "");
        };

    Map<String, Object> params = new LinkedHashMap<>();
    params.put("revocationEndpoint", "https://auth.example/revoke");
    params.put("token", "refresh-tok");
    params.put("clientId", "my-client");
    params.put("clientSecret", "s3cret");
    params.put("tokenTypeHint", "refresh_token");

    Map<String, Object> result = OauthSupport.revoke(params, poster);
    assertEquals(true, result.get("revoked"));
    assertEquals(200, result.get("status"));
    Map<String, String> body = form(calls.get(0).formBody);
    assertEquals("refresh-tok", body.get("token"));
    assertEquals("refresh_token", body.get("token_type_hint"));
    assertEquals("my-client", body.get("client_id"));
  }

  @Test
  void revokeTreats204AsSuccess() throws Exception {
    FormPoster poster =
        (url, formBody, headers) -> new FormPoster.HttpResponse(204, true, "");

    Map<String, Object> params = new LinkedHashMap<>();
    params.put("revocationEndpoint", "https://auth.example/revoke");
    params.put("token", "atok");
    params.put("clientId", "c");

    Map<String, Object> result = OauthSupport.revoke(params, poster);
    assertEquals(true, result.get("revoked"));
    assertEquals(204, result.get("status"));
  }

  @Test
  void revokeSurfacesErrors() {
    FormPoster poster =
        (url, formBody, headers) ->
            new FormPoster.HttpResponse(
                400,
                false,
                "{\"error\":\"invalid_request\",\"error_description\":\"token missing\"}");

    Map<String, Object> params = new LinkedHashMap<>();
    params.put("revocationEndpoint", "https://auth.example/revoke");
    params.put("token", "tok");
    params.put("clientId", "c");

    Exception ex = assertThrows(Exception.class, () -> OauthSupport.revoke(params, poster));
    assertTrue(ex.getMessage().contains("token missing"));
  }

  @Test
  void deviceAuthorizationPostsFormAndParsesResponse() throws Exception {
    List<Captured> calls = new ArrayList<>();
    FormPoster poster =
        (url, formBody, headers) -> {
          calls.add(new Captured(url, formBody, headers));
          return new FormPoster.HttpResponse(
              200,
              true,
              "{\"device_code\":\"dev-1\",\"user_code\":\"WDJB-MJHT\",\"verification_uri\":\"https://auth.example/device\",\"verification_uri_complete\":\"https://auth.example/device?user_code=WDJB-MJHT\",\"expires_in\":1800}");
        };

    Map<String, Object> params = new LinkedHashMap<>();
    params.put("deviceAuthorizationEndpoint", "https://auth.example/device");
    params.put("clientId", "my-client");
    params.put("clientSecret", "s3cret");
    params.put("scope", List.of("openid", "profile"));

    Map<String, Object> result = OauthSupport.deviceAuthorization(params, poster);
    assertEquals("dev-1", result.get("device_code"));
    assertEquals("WDJB-MJHT", result.get("user_code"));
    assertEquals("https://auth.example/device", result.get("verification_uri"));
    assertEquals(
        "https://auth.example/device?user_code=WDJB-MJHT",
        result.get("verification_uri_complete"));
    assertEquals(1800, result.get("expires_in"));
    assertEquals(5, result.get("interval"));
    assertEquals(1, calls.size());
    assertEquals("https://auth.example/device", calls.get(0).url);
    assertTrue(calls.get(0).headers.get("content-type").contains("application/x-www-form-urlencoded"));

    Map<String, String> body = form(calls.get(0).formBody);
    assertEquals("my-client", body.get("client_id"));
    assertEquals("s3cret", body.get("client_secret"));
    assertEquals("openid profile", body.get("scope"));
    assertFalse(body.containsKey("grant_type"));
  }

  @Test
  void deviceAuthorizationKeepsServerInterval() throws Exception {
    FormPoster poster =
        (url, formBody, headers) ->
            new FormPoster.HttpResponse(
                200,
                true,
                "{\"device_code\":\"dev-1\",\"user_code\":\"ABCD-EFGH\",\"verification_uri\":\"https://auth.example/device\",\"expires_in\":600,\"interval\":10}");

    Map<String, Object> params = new LinkedHashMap<>();
    params.put("deviceAuthorizationEndpoint", "https://auth.example/device");
    params.put("clientId", "my-client");

    Map<String, Object> result = OauthSupport.deviceAuthorization(params, poster);
    assertEquals(10, result.get("interval"));
    assertFalse(result.containsKey("verification_uri_complete"));
  }

  @Test
  void deviceAuthorizationSurfacesHttpErrors() {
    FormPoster poster =
        (url, formBody, headers) ->
            new FormPoster.HttpResponse(
                400,
                false,
                "{\"error\":\"invalid_client\",\"error_description\":\"unknown client\"}");

    Map<String, Object> params = new LinkedHashMap<>();
    params.put("deviceAuthorizationEndpoint", "https://auth.example/device");
    params.put("clientId", "c");

    Exception ex =
        assertThrows(Exception.class, () -> OauthSupport.deviceAuthorization(params, poster));
    assertTrue(ex.getMessage().contains("unknown client"));
    assertTrue(ex.getMessage().contains("Device authorization failed"));
  }

  @Test
  void deviceTokenReturnsTokens() throws Exception {
    List<Captured> calls = new ArrayList<>();
    FormPoster poster =
        (url, formBody, headers) -> {
          calls.add(new Captured(url, formBody, headers));
          return new FormPoster.HttpResponse(
              200,
              true,
              "{\"access_token\":\"atok\",\"token_type\":\"Bearer\",\"expires_in\":3600,\"refresh_token\":\"rtok\"}");
        };

    Map<String, Object> params = new LinkedHashMap<>();
    params.put("tokenEndpoint", "https://auth.example/token");
    params.put("deviceCode", "dev-1");
    params.put("clientId", "my-client");
    params.put("clientSecret", "s3cret");

    Map<String, Object> result = OauthSupport.deviceToken(params, poster);
    assertEquals("atok", result.get("access_token"));
    assertEquals("rtok", result.get("refresh_token"));
    assertEquals(1, calls.size());
    assertTrue(calls.get(0).headers.get("content-type").contains("application/x-www-form-urlencoded"));

    Map<String, String> body = form(calls.get(0).formBody);
    assertEquals("urn:ietf:params:oauth:grant-type:device_code", body.get("grant_type"));
    assertEquals("dev-1", body.get("device_code"));
    assertEquals("my-client", body.get("client_id"));
    assertEquals("s3cret", body.get("client_secret"));
  }

  @Test
  void deviceTokenAuthorizationPendingDoesNotThrow() throws Exception {
    FormPoster poster =
        (url, formBody, headers) ->
            new FormPoster.HttpResponse(
                400,
                false,
                "{\"error\":\"authorization_pending\",\"error_description\":\"authorization pending\"}");

    Map<String, Object> params = new LinkedHashMap<>();
    params.put("tokenEndpoint", "https://auth.example/token");
    params.put("deviceCode", "dev-1");
    params.put("clientId", "my-client");

    Map<String, Object> result = OauthSupport.deviceToken(params, poster);
    assertEquals("authorization_pending", result.get("error"));
    assertEquals("authorization pending", result.get("error_description"));
    assertFalse(result.containsKey("access_token"));
    assertFalse(result.containsKey("interval_increase"));
  }

  @Test
  void deviceTokenSlowDownDoesNotThrow() throws Exception {
    FormPoster withInterval =
        (url, formBody, headers) ->
            new FormPoster.HttpResponse(
                400,
                false,
                "{\"error\":\"slow_down\",\"error_description\":\"slow down\",\"interval\":15}");

    Map<String, Object> params = new LinkedHashMap<>();
    params.put("tokenEndpoint", "https://auth.example/token");
    params.put("deviceCode", "dev-1");
    params.put("clientId", "my-client");

    Map<String, Object> hinted = OauthSupport.deviceToken(params, withInterval);
    assertEquals("slow_down", hinted.get("error"));
    assertEquals("slow down", hinted.get("error_description"));
    assertEquals(15, hinted.get("interval"));
    assertFalse(hinted.containsKey("interval_increase"));

    FormPoster withoutInterval =
        (url, formBody, headers) ->
            new FormPoster.HttpResponse(400, false, "{\"error\":\"slow_down\"}");
    Map<String, Object> bump = OauthSupport.deviceToken(params, withoutInterval);
    assertEquals("slow_down", bump.get("error"));
    assertFalse(bump.containsKey("error_description"));
    assertFalse(bump.containsKey("interval"));
    assertEquals(5, bump.get("interval_increase"));
  }

  @Test
  void deviceTokenTerminalErrorsThrow() {
    Map<String, Object> params = new LinkedHashMap<>();
    params.put("tokenEndpoint", "https://auth.example/token");
    params.put("deviceCode", "dev-1");
    params.put("clientId", "my-client");

    FormPoster expired =
        (url, formBody, headers) ->
            new FormPoster.HttpResponse(
                400,
                false,
                "{\"error\":\"expired_token\",\"error_description\":\"device code expired\"}");
    Exception expiredEx =
        assertThrows(Exception.class, () -> OauthSupport.deviceToken(params, expired));
    assertTrue(expiredEx.getMessage().contains("device code expired"));
    assertTrue(expiredEx.getMessage().contains("Device token request failed"));

    FormPoster denied =
        (url, formBody, headers) ->
            new FormPoster.HttpResponse(
                400,
                false,
                "{\"error\":\"access_denied\",\"error_description\":\"user denied the request\"}");
    Exception deniedEx =
        assertThrows(Exception.class, () -> OauthSupport.deviceToken(params, denied));
    assertTrue(deniedEx.getMessage().contains("user denied the request"));
  }


  @Test
  void discoverFromIssuerFetchesOidcMetadata() throws Exception {
    List<GetCaptured> calls = new ArrayList<>();
    JsonGetClient getter =
        (url, headers) -> {
          calls.add(new GetCaptured(url, headers));
          return new FormPoster.HttpResponse(
              200,
              true,
              "{"
                  + "\"issuer\":\"https://auth.example\","
                  + "\"authorization_endpoint\":\"https://auth.example/authorize\","
                  + "\"token_endpoint\":\"https://auth.example/token\","
                  + "\"jwks_uri\":\"https://auth.example/jwks\","
                  + "\"userinfo_endpoint\":\"https://auth.example/userinfo\","
                  + "\"introspection_endpoint\":\"https://auth.example/introspect\","
                  + "\"revocation_endpoint\":\"https://auth.example/revoke\","
                  + "\"device_authorization_endpoint\":\"https://auth.example/device\","
                  + "\"scopes_supported\":[\"openid\",\"profile\"],"
                  + "\"grant_types_supported\":[\"authorization_code\",\"refresh_token\"],"
                  + "\"code_challenge_methods_supported\":[\"S256\"],"
                  + "\"claims_supported\":[\"sub\",\"name\"]"
                  + "}");
        };

    Map<String, Object> params = new LinkedHashMap<>();
    params.put("issuer", "https://auth.example");

    Map<String, Object> result = OauthSupport.discover(params, getter);
    assertEquals("https://auth.example", result.get("issuer"));
    assertEquals("https://auth.example/authorize", result.get("authorization_endpoint"));
    assertEquals("https://auth.example/token", result.get("token_endpoint"));
    assertEquals("https://auth.example/jwks", result.get("jwks_uri"));
    assertEquals("https://auth.example/userinfo", result.get("userinfo_endpoint"));
    assertEquals("https://auth.example/introspect", result.get("introspection_endpoint"));
    assertEquals("https://auth.example/revoke", result.get("revocation_endpoint"));
    assertEquals("https://auth.example/device", result.get("device_authorization_endpoint"));
    assertEquals(List.of("openid", "profile"), result.get("scopes_supported"));
    assertEquals(List.of("authorization_code", "refresh_token"), result.get("grant_types_supported"));
    assertEquals(List.of("S256"), result.get("code_challenge_methods_supported"));
    assertFalse(result.containsKey("claims_supported"));
    assertEquals(1, calls.size());
    assertEquals(
        "https://auth.example/.well-known/openid-configuration", calls.get(0).url);
    assertTrue(calls.get(0).headers.get("accept").contains("application/json"));
  }

  @Test
  void discoverFallsBackToOauthAsMetadataOnOidc404() throws Exception {
    List<String> urls = new ArrayList<>();
    JsonGetClient getter =
        (url, headers) -> {
          urls.add(url);
          if (url.endsWith("/.well-known/openid-configuration")) {
            return new FormPoster.HttpResponse(404, false, "not found");
          }
          return new FormPoster.HttpResponse(
              200,
              true,
              "{\"issuer\":\"https://auth.example\",\"token_endpoint\":\"https://auth.example/token\"}");
        };

    Map<String, Object> params = new LinkedHashMap<>();
    params.put("issuer", "https://auth.example/");

    Map<String, Object> result = OauthSupport.discover(params, getter);
    assertEquals("https://auth.example", result.get("issuer"));
    assertEquals("https://auth.example/token", result.get("token_endpoint"));
    assertEquals(2, urls.size());
    assertEquals("https://auth.example/.well-known/openid-configuration", urls.get(0));
    assertEquals("https://auth.example/.well-known/oauth-authorization-server", urls.get(1));
  }

  @Test
  void discoverUsesDirectMetadataUrl() throws Exception {
    List<GetCaptured> calls = new ArrayList<>();
    JsonGetClient getter =
        (url, headers) -> {
          calls.add(new GetCaptured(url, headers));
          return new FormPoster.HttpResponse(
              200,
              true,
              "{\"issuer\":\"https://idp.example\",\"authorization_endpoint\":\"https://idp.example/a\"}");
        };

    Map<String, Object> params = new LinkedHashMap<>();
    params.put("metadataUrl", "https://idp.example/custom/openid-configuration");

    Map<String, Object> result = OauthSupport.discover(params, getter);
    assertEquals("https://idp.example", result.get("issuer"));
    assertEquals(1, calls.size());
    assertEquals("https://idp.example/custom/openid-configuration", calls.get(0).url);
  }

  @Test
  void discoverOmitsAbsentFocusKeys() throws Exception {
    JsonGetClient getter =
        (url, headers) ->
            new FormPoster.HttpResponse(
                200,
                true,
                "{\"issuer\":\"https://auth.example\",\"token_endpoint\":\"https://auth.example/token\"}");

    Map<String, Object> params = new LinkedHashMap<>();
    params.put("issuer", "https://auth.example");

    Map<String, Object> result = OauthSupport.discover(params, getter);
    assertEquals(2, result.size());
    assertTrue(result.containsKey("issuer"));
    assertTrue(result.containsKey("token_endpoint"));
    assertFalse(result.containsKey("userinfo_endpoint"));
  }

  @Test
  void discoverSurfacesNon2xx() {
    JsonGetClient getter =
        (url, headers) -> new FormPoster.HttpResponse(500, false, "boom");

    Map<String, Object> params = new LinkedHashMap<>();
    params.put("issuer", "https://auth.example");

    Exception ex = assertThrows(Exception.class, () -> OauthSupport.discover(params, getter));
    assertTrue(ex.getMessage().contains("HTTP 500"));
    assertTrue(ex.getMessage().contains("Metadata discovery failed"));
  }

  @Test
  void discoverRejectsInvalidJson() {
    JsonGetClient getter =
        (url, headers) -> new FormPoster.HttpResponse(200, true, "not-json");

    Map<String, Object> params = new LinkedHashMap<>();
    params.put("metadataUrl", "https://auth.example/meta");

    Exception ex = assertThrows(Exception.class, () -> OauthSupport.discover(params, getter));
    assertTrue(ex.getMessage().contains("invalid JSON"));
  }

  @Test
  void discoverRequiresIssuerInResponse() {
    JsonGetClient getter =
        (url, headers) ->
            new FormPoster.HttpResponse(
                200, true, "{\"token_endpoint\":\"https://auth.example/token\"}");

    Map<String, Object> params = new LinkedHashMap<>();
    params.put("metadataUrl", "https://auth.example/meta");

    Exception ex = assertThrows(Exception.class, () -> OauthSupport.discover(params, getter));
    assertTrue(ex.getMessage().contains("missing issuer"));
  }

  @Test
  void discoverRequiresExactlyOneOfIssuerOrMetadataUrl() {
    Exception neither =
        assertThrows(Exception.class, () -> OauthSupport.discover(new LinkedHashMap<>()));
    assertTrue(neither.getMessage().contains("exactly one"));

    Map<String, Object> both = new LinkedHashMap<>();
    both.put("issuer", "https://auth.example");
    both.put("metadataUrl", "https://auth.example/meta");
    Exception bothEx = assertThrows(Exception.class, () -> OauthSupport.discover(both));
    assertTrue(bothEx.getMessage().contains("exactly one"));
  }

  @Test
  void resolveOidcDiscoveryUrlNormalizesTrailingSlashAndWellKnown() {
    assertEquals(
        "https://auth.example/.well-known/openid-configuration",
        OauthSupport.resolveOidcDiscoveryUrl("https://auth.example"));
    assertEquals(
        "https://auth.example/.well-known/openid-configuration",
        OauthSupport.resolveOidcDiscoveryUrl("https://auth.example/"));
    assertEquals(
        "https://auth.example/.well-known/openid-configuration",
        OauthSupport.resolveOidcDiscoveryUrl(
            "https://auth.example/.well-known/openid-configuration"));
    assertEquals(
        "https://auth.example/.well-known/oauth-authorization-server",
        OauthSupport.resolveOidcDiscoveryUrl(
            "https://auth.example/.well-known/oauth-authorization-server"));
  }

  @Test
  void resolveOauthAsDiscoveryUrlFromIssuerAndOidcPath() {
    assertEquals(
        "https://auth.example/.well-known/oauth-authorization-server",
        OauthSupport.resolveOauthAsDiscoveryUrl("https://auth.example"));
    assertEquals(
        "https://auth.example/.well-known/oauth-authorization-server",
        OauthSupport.resolveOauthAsDiscoveryUrl(
            "https://auth.example/.well-known/openid-configuration"));
  }

  @Test
  void userinfoSendsBearerAndReturnsJson() throws Exception {
    List<GetCaptured> calls = new ArrayList<>();
    JsonGetClient getter =
        (url, headers) -> {
          calls.add(new GetCaptured(url, headers));
          return new FormPoster.HttpResponse(
              200, true, "{\"sub\":\"user-1\",\"name\":\"Alice\",\"email\":\"a@example.com\"}");
        };

    Map<String, Object> params = new LinkedHashMap<>();
    params.put("userinfoEndpoint", "https://auth.example/userinfo");
    params.put("accessToken", "atok-secret");

    Map<String, Object> result = OauthSupport.userinfo(params, getter);
    assertEquals("user-1", result.get("sub"));
    assertEquals("Alice", result.get("name"));
    assertEquals(1, calls.size());
    assertEquals("https://auth.example/userinfo", calls.get(0).url);
    assertEquals("Bearer atok-secret", calls.get(0).headers.get("authorization"));
    assertTrue(calls.get(0).headers.get("accept").contains("application/json"));
  }

  @Test
  void userinfoSurfacesNon2xx() {
    JsonGetClient getter =
        (url, headers) ->
            new FormPoster.HttpResponse(
                401,
                false,
                "{\"error\":\"invalid_token\",\"error_description\":\"token expired\"}");

    Map<String, Object> params = new LinkedHashMap<>();
    params.put("userinfoEndpoint", "https://auth.example/userinfo");
    params.put("accessToken", "bad");

    Exception ex = assertThrows(Exception.class, () -> OauthSupport.userinfo(params, getter));
    assertTrue(ex.getMessage().contains("token expired"));
    assertTrue(ex.getMessage().contains("UserInfo request failed"));
  }

  @Test
  void userinfoRequiresAccessTokenAndEndpoint() {
    Map<String, Object> missingToken = new LinkedHashMap<>();
    missingToken.put("userinfoEndpoint", "https://auth.example/userinfo");
    Exception tokEx =
        assertThrows(Exception.class, () -> OauthSupport.userinfo(missingToken));
    assertTrue(tokEx.getMessage().contains("accessToken"));

    Map<String, Object> missingEndpoint = new LinkedHashMap<>();
    missingEndpoint.put("accessToken", "atok");
    Exception epEx =
        assertThrows(Exception.class, () -> OauthSupport.userinfo(missingEndpoint));
    assertTrue(epEx.getMessage().contains("userinfoEndpoint"));
  }

  @Test
  void userinfoRejectsInvalidJson() {
    JsonGetClient getter =
        (url, headers) -> new FormPoster.HttpResponse(200, true, "<html>nope</html>");

    Map<String, Object> params = new LinkedHashMap<>();
    params.put("userinfoEndpoint", "https://auth.example/userinfo");
    params.put("accessToken", "atok");

    Exception ex = assertThrows(Exception.class, () -> OauthSupport.userinfo(params, getter));
    assertTrue(ex.getMessage().contains("invalid JSON"));
    assertTrue(ex.getMessage().contains("UserInfo request failed"));
  }


  @Test
  void preferEnvOverFlagPrefersNonEmptyEnv() {
    assertEquals("from-env", OauthSupport.preferEnvOverFlag("from-env", "from-flag"));
    assertEquals("from-flag", OauthSupport.preferEnvOverFlag(null, "from-flag"));
    assertEquals("from-flag", OauthSupport.preferEnvOverFlag("", "from-flag"));
    assertNull(OauthSupport.preferEnvOverFlag(null, null));
    assertEquals("", OauthSupport.preferEnvOverFlag("", ""));
  }

  private record Captured(String url, String formBody, Map<String, String> headers) {}

  private record GetCaptured(String url, Map<String, String> headers) {}

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
