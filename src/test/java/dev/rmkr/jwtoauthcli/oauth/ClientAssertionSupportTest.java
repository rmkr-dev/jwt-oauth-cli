package dev.rmkr.jwtoauthcli.oauth;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import dev.rmkr.jwtoauthcli.http.FormPoster;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class ClientAssertionSupportTest {

  private static final String TOKEN_URL = "https://auth.example/oauth2/token";
  private static final String SECRET = "0123456789abcdef0123456789abcdef-client-secret";
  private static final String TOKEN_JSON =
      "{\"access_token\":\"atok\",\"token_type\":\"Bearer\",\"expires_in\":300}";

  private static RSAKey rsaKey;
  private static ECKey ecKey;

  @TempDir Path tmp;

  @BeforeAll
  static void keys() throws Exception {
    rsaKey = new RSAKeyGenerator(2048).keyID("rsa-client-1").generate();
    ecKey = new ECKeyGenerator(Curve.P_256).keyID("ec-client-1").generate();
  }

  private record Call(String url, Map<String, String> form, Map<String, String> headers) {}

  private static FormPoster recorder(List<Call> calls, int status, String body) {
    return (url, formBody, headers) -> {
      calls.add(new Call(url, parseForm(formBody), new LinkedHashMap<>(headers)));
      return new FormPoster.HttpResponse(status, status >= 200 && status < 300, body);
    };
  }

  private static Map<String, String> parseForm(String form) {
    Map<String, String> out = new LinkedHashMap<>();
    for (String pair : form.split("&")) {
      int eq = pair.indexOf('=');
      out.put(
          URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8),
          URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8));
    }
    return out;
  }

  private Path writeJwk(String name, String json) throws Exception {
    Path p = tmp.resolve(name);
    Files.writeString(p, json);
    return p;
  }

  private static Map<String, Object> clientCredsParams() {
    Map<String, Object> params = new LinkedHashMap<>();
    params.put("tokenEndpoint", TOKEN_URL);
    params.put("clientId", "svc-client");
    params.put("scope", "api.read");
    return params;
  }

  // ---- assertion building ----

  @Test
  void privateKeyJwtAssertionHasExpectedClaimsAndHeader() throws Exception {
    Map<String, Object> opts = new LinkedHashMap<>();
    opts.put("clientId", "svc-client");
    opts.put("audience", TOKEN_URL);
    opts.put("clientJwk", rsaKey.toJSONString());
    opts.put("now", 1_900_000_000L);
    opts.put("jti", "fixed-jti");

    Map<String, Object> out = ClientAssertionSupport.buildAssertion(opts);
    assertEquals(ClientAssertionSupport.JWT_BEARER_ASSERTION_TYPE, out.get("client_assertion_type"));

    SignedJWT jwt = SignedJWT.parse((String) out.get("client_assertion"));
    assertEquals(JWSAlgorithm.RS256, jwt.getHeader().getAlgorithm());
    assertEquals("rsa-client-1", jwt.getHeader().getKeyID());
    assertEquals("JWT", jwt.getHeader().getType().getType());

    JWTClaimsSet claims = jwt.getJWTClaimsSet();
    assertEquals("svc-client", claims.getIssuer());
    assertEquals("svc-client", claims.getSubject());
    assertEquals(List.of(TOKEN_URL), claims.getAudience());
    assertEquals("fixed-jti", claims.getJWTID());
    assertEquals(1_900_000_000L, claims.getIssueTime().getTime() / 1000L);
    assertEquals(1_900_000_060L, claims.getExpirationTime().getTime() / 1000L);
    assertTrue(jwt.verify(new RSASSAVerifier(rsaKey.toPublicJWK())));
  }

  @Test
  void jtiIsRandomPerAssertionAndLifetimeIsConfigurable() throws Exception {
    Map<String, Object> opts = new LinkedHashMap<>();
    opts.put("clientId", "c");
    opts.put("audience", TOKEN_URL);
    opts.put("clientJwk", ecKey.toJSONString());
    opts.put("lifetimeSeconds", 120L);

    SignedJWT a = SignedJWT.parse((String) ClientAssertionSupport.buildAssertion(opts).get("client_assertion"));
    SignedJWT b = SignedJWT.parse((String) ClientAssertionSupport.buildAssertion(opts).get("client_assertion"));
    assertNotEquals(a.getJWTClaimsSet().getJWTID(), b.getJWTClaimsSet().getJWTID());
    long iat = a.getJWTClaimsSet().getIssueTime().getTime() / 1000L;
    long exp = a.getJWTClaimsSet().getExpirationTime().getTime() / 1000L;
    assertEquals(120L, exp - iat);
  }

  @Test
  void ecKeyDefaultsToCurveAlgorithmAndVerifies() throws Exception {
    Map<String, Object> opts = new LinkedHashMap<>();
    opts.put("clientId", "c");
    opts.put("audience", TOKEN_URL);
    opts.put("clientJwk", ecKey.toJSONString());

    SignedJWT jwt = SignedJWT.parse((String) ClientAssertionSupport.buildAssertion(opts).get("client_assertion"));
    assertEquals(JWSAlgorithm.ES256, jwt.getHeader().getAlgorithm());
    assertEquals("ec-client-1", jwt.getHeader().getKeyID());
    assertTrue(jwt.verify(new ECDSAVerifier(ecKey.toPublicJWK())));
  }

  @Test
  void ps256FromJwksFileWithSinglePrivateKey() throws Exception {
    Path file = writeJwk("client.jwks", new JWKSet(rsaKey).toString(false));
    Map<String, Object> opts = new LinkedHashMap<>();
    opts.put("clientId", "c");
    opts.put("audience", TOKEN_URL);
    opts.put("clientJwkFile", file.toString());
    opts.put("alg", "PS256");

    SignedJWT jwt = SignedJWT.parse((String) ClientAssertionSupport.buildAssertion(opts).get("client_assertion"));
    assertEquals(JWSAlgorithm.PS256, jwt.getHeader().getAlgorithm());
    assertTrue(jwt.verify(new RSASSAVerifier(rsaKey.toPublicJWK())));
  }

  @Test
  void clientSecretJwtUsesHs256ByDefaultAndVerifiesWithSecret() throws Exception {
    Map<String, Object> opts = new LinkedHashMap<>();
    opts.put("clientId", "web-client");
    opts.put("audience", TOKEN_URL);
    opts.put("method", "client_secret_jwt");
    opts.put("clientSecret", SECRET);

    Map<String, Object> out = ClientAssertionSupport.buildAssertion(opts);
    SignedJWT jwt = SignedJWT.parse((String) out.get("client_assertion"));
    assertEquals(JWSAlgorithm.HS256, jwt.getHeader().getAlgorithm());
    assertNull(jwt.getHeader().getKeyID());
    assertEquals("web-client", jwt.getJWTClaimsSet().getIssuer());
    assertTrue(jwt.verify(new MACVerifier(SECRET.getBytes(StandardCharsets.UTF_8))));
    assertFalse(String.valueOf(out).contains(SECRET));
  }

  @Test
  void clientSecretJwtHonoursHs512() throws Exception {
    String longSecret = SECRET + SECRET;
    Map<String, Object> opts = new LinkedHashMap<>();
    opts.put("clientId", "c");
    opts.put("audience", TOKEN_URL);
    opts.put("method", "client_secret_jwt");
    opts.put("clientSecret", longSecret);
    opts.put("alg", "HS512");

    SignedJWT jwt = SignedJWT.parse((String) ClientAssertionSupport.buildAssertion(opts).get("client_assertion"));
    assertEquals(JWSAlgorithm.HS512, jwt.getHeader().getAlgorithm());
    assertTrue(jwt.verify(new MACVerifier(longSecret.getBytes(StandardCharsets.UTF_8))));
  }

  // ---- error cases ----

  @Test
  void privateKeyJwtWithoutJwkFails() {
    Map<String, Object> params = clientCredsParams();
    params.put("clientAuth", "private_key_jwt");
    List<Call> calls = new ArrayList<>();
    IllegalArgumentException ex =
        assertThrows(
            IllegalArgumentException.class,
            () -> OauthSupport.clientCredentials(params, recorder(calls, 200, TOKEN_JSON)));
    assertTrue(ex.getMessage().contains("--client-jwk-file"), ex.getMessage());
    assertTrue(calls.isEmpty());
  }

  @Test
  void missingJwkFileIsReported() {
    Map<String, Object> opts = new LinkedHashMap<>();
    opts.put("clientId", "c");
    opts.put("audience", TOKEN_URL);
    opts.put("clientJwkFile", tmp.resolve("nope.json").toString());
    IllegalArgumentException ex =
        assertThrows(IllegalArgumentException.class, () -> ClientAssertionSupport.buildAssertion(opts));
    assertTrue(ex.getMessage().contains("Cannot read client JWK file"), ex.getMessage());
  }

  @Test
  void publicOnlyJwkIsRejected() {
    Map<String, Object> opts = new LinkedHashMap<>();
    opts.put("clientId", "c");
    opts.put("audience", TOKEN_URL);
    opts.put("clientJwk", rsaKey.toPublicJWK().toJSONString());
    IllegalArgumentException ex =
        assertThrows(IllegalArgumentException.class, () -> ClientAssertionSupport.buildAssertion(opts));
    assertTrue(ex.getMessage().contains("exactly one private"), ex.getMessage());
  }

  @Test
  void algorithmMismatchesAreRejected() {
    Map<String, Object> rsaWithEs = new LinkedHashMap<>();
    rsaWithEs.put("clientId", "c");
    rsaWithEs.put("audience", TOKEN_URL);
    rsaWithEs.put("clientJwk", rsaKey.toJSONString());
    rsaWithEs.put("alg", "ES256");
    assertTrue(
        assertThrows(IllegalArgumentException.class, () -> ClientAssertionSupport.buildAssertion(rsaWithEs))
            .getMessage()
            .contains("does not match RSA"));

    Map<String, Object> ecWrongCurve = new LinkedHashMap<>(rsaWithEs);
    ecWrongCurve.put("clientJwk", ecKey.toJSONString());
    ecWrongCurve.put("alg", "ES384");
    assertTrue(
        assertThrows(IllegalArgumentException.class, () -> ClientAssertionSupport.buildAssertion(ecWrongCurve))
            .getMessage()
            .contains("does not match curve"));

    Map<String, Object> hmacWithRs = new LinkedHashMap<>();
    hmacWithRs.put("clientId", "c");
    hmacWithRs.put("audience", TOKEN_URL);
    hmacWithRs.put("method", "client_secret_jwt");
    hmacWithRs.put("clientSecret", SECRET);
    hmacWithRs.put("alg", "RS256");
    assertTrue(
        assertThrows(IllegalArgumentException.class, () -> ClientAssertionSupport.buildAssertion(hmacWithRs))
            .getMessage()
            .contains("HMAC algorithm"));
  }

  @Test
  void secretBasedModesRequireSecret() {
    for (String mode : List.of("basic", "post", "client_secret_jwt")) {
      Map<String, Object> params = clientCredsParams();
      params.put("clientAuth", mode);
      List<Call> calls = new ArrayList<>();
      IllegalArgumentException ex =
          assertThrows(
              IllegalArgumentException.class,
              () -> OauthSupport.clientCredentials(params, recorder(calls, 200, TOKEN_JSON)),
              mode);
      assertTrue(ex.getMessage().contains("requires a client secret"), mode + ": " + ex.getMessage());
      assertTrue(calls.isEmpty());
    }
  }

  @Test
  void shortHmacSecretAndBadLifetimeAreRejected() {
    Map<String, Object> opts = new LinkedHashMap<>();
    opts.put("clientId", "c");
    opts.put("audience", TOKEN_URL);
    opts.put("method", "client_secret_jwt");
    opts.put("clientSecret", "short");
    assertTrue(
        assertThrows(IllegalArgumentException.class, () -> ClientAssertionSupport.buildAssertion(opts))
            .getMessage()
            .contains("too short for HS256"));

    opts.put("clientSecret", SECRET);
    opts.put("lifetimeSeconds", 0L);
    assertThrows(IllegalArgumentException.class, () -> ClientAssertionSupport.buildAssertion(opts));
  }

  @Test
  void unknownClientAuthAndStrayJwkFileAreRejected() {
    assertThrows(IllegalArgumentException.class, () -> ClientAssertionSupport.Method.parse("mtls"));

    Map<String, Object> params = clientCredsParams();
    params.put("clientSecret", SECRET);
    params.put("clientJwkFile", "/tmp/client.jwk");
    List<Call> calls = new ArrayList<>();
    IllegalArgumentException ex =
        assertThrows(
            IllegalArgumentException.class,
            () -> OauthSupport.clientCredentials(params, recorder(calls, 200, TOKEN_JSON)));
    assertTrue(ex.getMessage().contains("private_key_jwt"), ex.getMessage());
    assertTrue(calls.isEmpty());
  }

  @Test
  void methodParseAcceptsRegisteredNames() {
    assertNull(ClientAssertionSupport.Method.parse(null));
    assertEquals(ClientAssertionSupport.Method.CLIENT_SECRET_BASIC, ClientAssertionSupport.Method.parse("client_secret_basic"));
    assertEquals(ClientAssertionSupport.Method.CLIENT_SECRET_POST, ClientAssertionSupport.Method.parse("POST"));
    assertEquals(ClientAssertionSupport.Method.PRIVATE_KEY_JWT, ClientAssertionSupport.Method.parse("private-key-jwt"));
    assertTrue(ClientAssertionSupport.requiresSecret("client_secret_jwt"));
    assertFalse(ClientAssertionSupport.requiresSecret("private_key_jwt"));
    assertFalse(ClientAssertionSupport.requiresSecret(null));
  }

  // ---- form params per auth mode ----

  @Test
  void defaultModeKeepsLegacyFormBody() throws Exception {
    Map<String, Object> params = clientCredsParams();
    params.put("clientSecret", SECRET);
    List<Call> calls = new ArrayList<>();
    OauthSupport.clientCredentials(params, recorder(calls, 200, TOKEN_JSON));

    Call call = calls.get(0);
    assertEquals(
        List.of("grant_type", "client_id", "client_secret", "scope"),
        new ArrayList<>(call.form().keySet()));
    assertEquals(SECRET, call.form().get("client_secret"));
    assertFalse(call.headers().containsKey("authorization"));
  }

  @Test
  void postModeSendsSecretInBody() throws Exception {
    Map<String, Object> params = clientCredsParams();
    params.put("clientSecret", SECRET);
    params.put("clientAuth", "post");
    List<Call> calls = new ArrayList<>();
    OauthSupport.clientCredentials(params, recorder(calls, 200, TOKEN_JSON));
    assertEquals(SECRET, calls.get(0).form().get("client_secret"));
    assertFalse(calls.get(0).form().containsKey("client_assertion"));
  }

  @Test
  void basicModeMovesSecretToAuthorizationHeader() throws Exception {
    Map<String, Object> params = clientCredsParams();
    params.put("clientId", "svc client");
    params.put("clientSecret", "s3cr:t+");
    params.put("clientAuth", "basic");
    List<Call> calls = new ArrayList<>();
    OauthSupport.clientCredentials(params, recorder(calls, 200, TOKEN_JSON));

    Call call = calls.get(0);
    assertFalse(call.form().containsKey("client_secret"));
    String auth = call.headers().get("authorization");
    assertTrue(auth.startsWith("Basic "));
    String decoded = new String(Base64.getDecoder().decode(auth.substring(6)), StandardCharsets.UTF_8);
    assertEquals("svc+client:s3cr%3At%2B", decoded);
  }

  @Test
  void privateKeyJwtModeSendsAssertionAndNoSecret() throws Exception {
    Path file = writeJwk("client.jwk", rsaKey.toJSONString());
    Map<String, Object> params = clientCredsParams();
    params.put("clientSecret", SECRET); // e.g. stray env var; must not be sent
    params.put("clientAuth", "private_key_jwt");
    params.put("clientJwkFile", file.toString());
    List<Call> calls = new ArrayList<>();
    Map<String, Object> result = OauthSupport.clientCredentials(params, recorder(calls, 200, TOKEN_JSON));
    assertEquals("atok", result.get("access_token"));

    Map<String, String> form = calls.get(0).form();
    assertFalse(form.containsKey("client_secret"));
    assertEquals("client_credentials", form.get("grant_type"));
    assertEquals("svc-client", form.get("client_id"));
    assertEquals(ClientAssertionSupport.JWT_BEARER_ASSERTION_TYPE, form.get("client_assertion_type"));
    SignedJWT jwt = SignedJWT.parse(form.get("client_assertion"));
    assertTrue(jwt.verify(new RSASSAVerifier(rsaKey.toPublicJWK())));
    assertEquals(List.of(TOKEN_URL), jwt.getJWTClaimsSet().getAudience());
    assertFalse(calls.get(0).headers().containsKey("authorization"));
  }

  @Test
  void clientSecretJwtModeOnRefreshUsesOverriddenAudience() throws Exception {
    Map<String, Object> params = new LinkedHashMap<>();
    params.put("tokenEndpoint", TOKEN_URL);
    params.put("refreshToken", "rtok");
    params.put("clientId", "web-client");
    params.put("clientSecret", SECRET);
    params.put("clientAuth", "client_secret_jwt");
    params.put("assertionAudience", "https://auth.example");
    List<Call> calls = new ArrayList<>();
    OauthSupport.refreshToken(params, recorder(calls, 200, TOKEN_JSON));

    Map<String, String> form = calls.get(0).form();
    assertFalse(form.containsKey("client_secret"));
    SignedJWT jwt = SignedJWT.parse(form.get("client_assertion"));
    assertEquals(List.of("https://auth.example"), jwt.getJWTClaimsSet().getAudience());
    assertTrue(jwt.verify(new MACVerifier(SECRET.getBytes(StandardCharsets.UTF_8))));
  }

  @Test
  void exchangeAndDeviceTokenAcceptJwtAuth() throws Exception {
    String jwk = ecKey.toJSONString();

    Map<String, Object> exchange = new LinkedHashMap<>();
    exchange.put("tokenEndpoint", TOKEN_URL);
    exchange.put("code", "abc");
    exchange.put("redirectUri", "http://127.0.0.1:8080/cb");
    exchange.put("clientId", "app");
    exchange.put("codeVerifier", "verifier");
    exchange.put("clientAuth", "private_key_jwt");
    exchange.put("clientJwk", jwk);
    List<Call> calls = new ArrayList<>();
    OauthSupport.exchangeCode(exchange, recorder(calls, 200, TOKEN_JSON));
    assertEquals("verifier", calls.get(0).form().get("code_verifier"));
    assertTrue(calls.get(0).form().containsKey("client_assertion"));

    Map<String, Object> device = new LinkedHashMap<>();
    device.put("tokenEndpoint", TOKEN_URL);
    device.put("deviceCode", "dev-code");
    device.put("clientId", "app");
    device.put("clientAuth", "private_key_jwt");
    device.put("clientJwk", jwk);
    OauthSupport.deviceToken(device, recorder(calls, 200, TOKEN_JSON));
    assertEquals(ClientAssertionSupport.JWT_BEARER_ASSERTION_TYPE, calls.get(1).form().get("client_assertion_type"));
  }

  @Test
  void introspectAndRevokeDefaultAudienceIsTheirEndpoint() throws Exception {
    Map<String, Object> introspect = new LinkedHashMap<>();
    introspect.put("introspectionEndpoint", "https://auth.example/introspect");
    introspect.put("token", "atok");
    introspect.put("clientId", "rs");
    introspect.put("clientAuth", "private_key_jwt");
    introspect.put("clientJwk", rsaKey.toJSONString());
    List<Call> calls = new ArrayList<>();
    OauthSupport.introspect(introspect, recorder(calls, 200, "{\"active\":true}"));
    SignedJWT a = SignedJWT.parse(calls.get(0).form().get("client_assertion"));
    assertEquals(List.of("https://auth.example/introspect"), a.getJWTClaimsSet().getAudience());

    Map<String, Object> revoke = new LinkedHashMap<>();
    revoke.put("revocationEndpoint", "https://auth.example/revoke");
    revoke.put("token", "rtok");
    revoke.put("clientId", "rs");
    revoke.put("clientSecret", SECRET);
    revoke.put("clientAuth", "basic");
    Map<String, Object> out = OauthSupport.revoke(revoke, recorder(calls, 200, ""));
    assertEquals(true, out.get("revoked"));
    assertTrue(calls.get(1).headers().get("authorization").startsWith("Basic "));
    assertFalse(calls.get(1).form().containsKey("client_secret"));
  }
}
