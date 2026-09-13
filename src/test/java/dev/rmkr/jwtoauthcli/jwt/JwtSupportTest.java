package dev.rmkr.jwtoauthcli.jwt;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class JwtSupportTest {

  private static final String HMAC_SECRET = "test-hmac-secret-at-least-32-bytes!!";

  /** Build an unsigned JWT-like token from JSON header/payload (alg none). */
  static String makeToken(Map<String, Object> header, Map<String, Object> payload) {
    Base64.Encoder enc = Base64.getUrlEncoder().withoutPadding();
    String h =
        enc.encodeToString(toJson(header).getBytes(StandardCharsets.UTF_8));
    String p =
        enc.encodeToString(toJson(payload).getBytes(StandardCharsets.UTF_8));
    return h + "." + p + ".";
  }

  private static String toJson(Map<String, Object> obj) {
    try {
      return new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(obj);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  private static String signHs256(Map<String, Object> claims, String secret) throws Exception {
    JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
    for (Map.Entry<String, Object> e : claims.entrySet()) {
      Object v = e.getValue();
      if ("exp".equals(e.getKey()) || "iat".equals(e.getKey()) || "nbf".equals(e.getKey())) {
        builder.claim(e.getKey(), ((Number) v).longValue());
      } else if ("aud".equals(e.getKey()) && v instanceof List<?> list) {
        builder.audience(list.stream().map(String::valueOf).toList());
      } else {
        builder.claim(e.getKey(), v);
      }
    }
    // Nimbus Date claims for exp/iat when set via dedicated setters work better for verification
    if (claims.get("exp") instanceof Number n) {
      builder.expirationTime(new Date(n.longValue() * 1000L));
    }
    if (claims.get("iat") instanceof Number n) {
      builder.issueTime(new Date(n.longValue() * 1000L));
    }

    SignedJWT jwt =
        new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), builder.build());
    jwt.sign(new MACSigner(secret.getBytes(StandardCharsets.UTF_8)));
    return jwt.serialize();
  }

  @Test
  void decodesHeaderAndPayload() {
    Map<String, Object> header = new LinkedHashMap<>();
    header.put("alg", "none");
    header.put("typ", "JWT");
    Map<String, Object> payload = new LinkedHashMap<>();
    payload.put("sub", "user-1");
    payload.put("iss", "https://issuer.example");
    payload.put("aud", "api");

    String token = makeToken(header, payload);
    Map<String, Object> result = JwtSupport.decode(token);

    @SuppressWarnings("unchecked")
    Map<String, Object> h = (Map<String, Object>) result.get("header");
    @SuppressWarnings("unchecked")
    Map<String, Object> p = (Map<String, Object>) result.get("payload");

    assertEquals("none", h.get("alg"));
    assertEquals("JWT", h.get("typ"));
    assertEquals("user-1", p.get("sub"));
    assertEquals("https://issuer.example", p.get("iss"));
    assertEquals("api", p.get("aud"));
  }

  @Test
  void rejectsEmptyInput() {
    IllegalArgumentException ex =
        assertThrows(IllegalArgumentException.class, () -> JwtSupport.decode(""));
    assertTrue(ex.getMessage().contains("non-empty"));
  }

  @Test
  void rejectsMalformedSegments() {
    IllegalArgumentException ex =
        assertThrows(IllegalArgumentException.class, () -> JwtSupport.decode("onlyone"));
    assertTrue(ex.getMessage().contains("Invalid JWT"));
  }

  @Test
  void inspectReportsExpirationRelativeToFixedNow() {
    long now = 1_700_000_000L;
    Map<String, Object> header = new LinkedHashMap<>();
    header.put("alg", "HS256");
    header.put("typ", "JWT");
    header.put("kid", "k1");
    Map<String, Object> payload = new LinkedHashMap<>();
    payload.put("sub", "abc");
    payload.put("iss", "https://issuer.example");
    payload.put("exp", now + 60);
    payload.put("iat", now - 60);
    payload.put("nbf", now - 30);

    String token = makeToken(header, payload);
    Map<String, Object> result = JwtSupport.inspect(token, now);

    assertEquals(false, result.get("expired"));
    assertEquals(60L, ((Number) result.get("expiresInSeconds")).longValue());
    assertEquals(false, result.get("notYetValid"));

    @SuppressWarnings("unchecked")
    Map<String, Object> summary = (Map<String, Object>) result.get("summary");
    assertEquals("abc", summary.get("sub"));
    assertEquals("k1", summary.get("kid"));

    @SuppressWarnings("unchecked")
    Map<String, Object> time = (Map<String, Object>) result.get("time");
    @SuppressWarnings("unchecked")
    Map<String, Object> exp = (Map<String, Object>) time.get("exp");
    assertEquals(now + 60, ((Number) exp.get("unix")).longValue());
    assertNotNull(exp.get("iso"));
  }

  @Test
  void inspectMarksExpiredTokens() {
    long now = 1_700_000_000L;
    Map<String, Object> header = Map.of("alg", "none");
    Map<String, Object> payload = Map.of("exp", now - 1);
    String token = makeToken(header, payload);
    Map<String, Object> result = JwtSupport.inspect(token, now);
    assertEquals(true, result.get("expired"));
    assertTrue(((Number) result.get("expiresInSeconds")).longValue() < 0);
  }

  @Test
  void verifyHmacSuccess() throws Exception {
    long now = 1_700_000_000L;
    Map<String, Object> claims = new LinkedHashMap<>();
    claims.put("sub", "user-1");
    claims.put("iss", "https://issuer.example");
    claims.put("aud", List.of("api"));
    claims.put("exp", now + 300);
    claims.put("iat", now);

    String token = signHs256(claims, HMAC_SECRET);
    Map<String, Object> options = new LinkedHashMap<>();
    options.put("secret", HMAC_SECRET);
    options.put("iss", "https://issuer.example");
    options.put("aud", "api");
    options.put("expLeewaySeconds", 60L);
    options.put("nowSec", now);

    Map<String, Object> result = JwtSupport.verify(token, options);
    assertEquals(true, result.get("valid"));
    assertEquals("HS256", result.get("algorithm"));
    @SuppressWarnings("unchecked")
    Map<String, Object> payload = (Map<String, Object>) result.get("payload");
    assertEquals("user-1", payload.get("sub"));
    @SuppressWarnings("unchecked")
    Map<String, Object> checked = (Map<String, Object>) result.get("claimsChecked");
    assertEquals("https://issuer.example", checked.get("iss"));
    assertEquals("api", checked.get("aud"));
    assertTrue(checked.containsKey("exp"));
  }

  @Test
  void verifyHmacFailsWrongSecret() throws Exception {
    long now = 1_700_000_000L;
    Map<String, Object> claims = new LinkedHashMap<>();
    claims.put("sub", "user-1");
    claims.put("exp", now + 300);
    String token = signHs256(claims, HMAC_SECRET);

    Map<String, Object> options = new LinkedHashMap<>();
    options.put("secret", "wrong-secret-at-least-32-bytes-long!!");
    options.put("nowSec", now);

    IllegalArgumentException ex =
        assertThrows(IllegalArgumentException.class, () -> JwtSupport.verify(token, options));
    assertTrue(ex.getMessage().toLowerCase().contains("verification failed")
        || ex.getMessage().toLowerCase().contains("signature"));
  }

  @Test
  void verifyRejectsExpiredOutsideLeeway() throws Exception {
    long now = 1_700_000_000L;
    Map<String, Object> claims = new LinkedHashMap<>();
    claims.put("sub", "user-1");
    claims.put("exp", now - 120); // expired 120s ago
    String token = signHs256(claims, HMAC_SECRET);

    Map<String, Object> options = new LinkedHashMap<>();
    options.put("secret", HMAC_SECRET);
    options.put("expLeewaySeconds", 60L);
    options.put("nowSec", now);

    IllegalArgumentException ex =
        assertThrows(IllegalArgumentException.class, () -> JwtSupport.verify(token, options));
    assertTrue(ex.getMessage().contains("expired"));
  }

  @Test
  void verifyAllowsExpiredWithinLeeway() throws Exception {
    long now = 1_700_000_000L;
    Map<String, Object> claims = new LinkedHashMap<>();
    claims.put("sub", "user-1");
    claims.put("exp", now - 30); // expired 30s ago, leeway 60
    String token = signHs256(claims, HMAC_SECRET);

    Map<String, Object> options = new LinkedHashMap<>();
    options.put("secret", HMAC_SECRET);
    options.put("expLeewaySeconds", 60L);
    options.put("nowSec", now);

    Map<String, Object> result = JwtSupport.verify(token, options);
    assertEquals(true, result.get("valid"));
  }

  @Test
  void verifyRequiresExactlyOneKeySource() throws Exception {
    long now = 1_700_000_000L;
    Map<String, Object> claims = Map.of("sub", "u", "exp", now + 60);
    String token = signHs256(new LinkedHashMap<>(claims), HMAC_SECRET);

    IllegalArgumentException both =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                JwtSupport.verify(
                    token,
                    Map.of("secret", HMAC_SECRET, "jwksUrl", "https://example/.well-known/jwks.json")));
    assertTrue(both.getMessage().contains("exactly one"));

    IllegalArgumentException neither =
        assertThrows(IllegalArgumentException.class, () -> JwtSupport.verify(token, Map.of()));
    assertTrue(neither.getMessage().contains("exactly one"));
  }

  @Test
  void verifyJwksWithMockFetcher() throws Exception {
    long now = 1_700_000_000L;
    RSAKey rsa =
        new RSAKeyGenerator(2048).keyID("rsa-1").generate();
    JWTClaimsSet claims =
        new JWTClaimsSet.Builder()
            .subject("jwks-user")
            .issuer("https://issuer.example")
            .audience("api")
            .expirationTime(new Date((now + 300) * 1000L))
            .issueTime(new Date(now * 1000L))
            .build();
    SignedJWT jwt =
        new SignedJWT(
            new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsa.getKeyID()).build(), claims);
    jwt.sign(new RSASSASigner(rsa));
    String token = jwt.serialize();

    String jwksJson = new com.nimbusds.jose.jwk.JWKSet(rsa.toPublicJWK()).toString();

    Map<String, Object> options = new LinkedHashMap<>();
    options.put("jwksUrl", "https://auth.example/.well-known/jwks.json");
    options.put("jwksFetcher", (dev.rmkr.jwtoauthcli.http.JwksFetcher) url -> jwksJson);
    options.put("iss", "https://issuer.example");
    options.put("aud", "api");
    options.put("nowSec", now);

    Map<String, Object> result = JwtSupport.verify(token, options);
    assertEquals(true, result.get("valid"));
    assertEquals("RS256", result.get("algorithm"));
  }

  @Test
  void verifyIssuerMismatch() throws Exception {
    long now = 1_700_000_000L;
    Map<String, Object> claims = new LinkedHashMap<>();
    claims.put("sub", "user-1");
    claims.put("iss", "https://other.example");
    claims.put("exp", now + 300);
    String token = signHs256(claims, HMAC_SECRET);

    Map<String, Object> options = new LinkedHashMap<>();
    options.put("secret", HMAC_SECRET);
    options.put("iss", "https://issuer.example");
    options.put("nowSec", now);

    IllegalArgumentException ex =
        assertThrows(IllegalArgumentException.class, () -> JwtSupport.verify(token, options));
    assertTrue(ex.getMessage().contains("Issuer"));
  }
}
