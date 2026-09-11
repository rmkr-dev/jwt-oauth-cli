package dev.rmkr.jwtoauthcli.jwt;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class JwtSupportTest {

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
}
