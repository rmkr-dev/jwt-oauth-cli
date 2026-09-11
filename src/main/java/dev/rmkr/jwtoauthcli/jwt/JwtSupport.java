package dev.rmkr.jwtoauthcli.jwt;

import com.nimbusds.jose.Header;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;

import java.text.ParseException;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * JWT decode and inspect helpers.
 * Uses Nimbus JOSE+JWT for header/claims parsing. Signature verification is
 * intentionally out of scope; tokens are treated as opaque payloads for local
 * inspection only (matches jose decodeJwt / decodeProtectedHeader behavior).
 */
public final class JwtSupport {

  private JwtSupport() {}

  /**
   * Decode a JWT without verifying the signature.
   *
   * @param token JWT string
   * @return map with {@code header} and {@code payload} objects
   */
  public static Map<String, Object> decode(String token) {
    if (token == null || token.trim().isEmpty()) {
      throw new IllegalArgumentException("JWT token must be a non-empty string");
    }
    String trimmed = token.trim();
    String[] parts = trimmed.split("\\.", -1);
    if (parts.length < 2 || parts.length > 3) {
      throw new IllegalArgumentException(
          "Invalid JWT: expected 2 or 3 dot-separated segments");
    }
    if (parts[0].isEmpty() || parts[1].isEmpty()) {
      throw new IllegalArgumentException("Invalid JWT: expected 2 or 3 dot-separated segments");
    }

    try {
      Header header = Header.parse(new Base64URL(parts[0]));
      // Decode payload bytes as UTF-8 JSON for claims (ignore signature segment).
      String payloadJson = new Base64URL(parts[1]).decodeToString();
      JWTClaimsSet claims = JWTClaimsSet.parse(payloadJson);

      Map<String, Object> result = new LinkedHashMap<>();
      result.put("header", new LinkedHashMap<>(header.toJSONObject()));
      result.put("payload", new LinkedHashMap<>(claims.toJSONObject()));
      return result;
    } catch (ParseException e) {
      throw new IllegalArgumentException("Failed to decode JWT: " + e.getMessage(), e);
    } catch (IllegalArgumentException e) {
      throw new IllegalArgumentException("Failed to decode JWT: " + e.getMessage(), e);
    }
  }

  /**
   * Summarize claims useful for quick inspection (exp, iat, nbf, etc.).
   *
   * @param token JWT string
   * @param nowSec evaluation time in unix seconds; null uses current time
   */
  public static Map<String, Object> inspect(String token, Long nowSec) {
    long now = nowSec != null ? nowSec : Instant.now().getEpochSecond();

    Map<String, Object> decoded = decode(token);
    @SuppressWarnings("unchecked")
    Map<String, Object> header = (Map<String, Object>) decoded.get("header");
    @SuppressWarnings("unchecked")
    Map<String, Object> claims =
        new LinkedHashMap<>((Map<String, Object>) decoded.get("payload"));

    Map<String, Object> summary = new LinkedHashMap<>();
    summary.put("alg", header.getOrDefault("alg", null));
    summary.put("typ", header.getOrDefault("typ", null));
    summary.put("kid", header.getOrDefault("kid", null));
    summary.put("iss", claims.getOrDefault("iss", null));
    summary.put("sub", claims.getOrDefault("sub", null));
    summary.put("aud", claims.getOrDefault("aud", null));
    summary.put("jti", claims.getOrDefault("jti", null));

    Map<String, Object> timeClaims = new LinkedHashMap<>();
    for (String key : new String[] {"exp", "iat", "nbf"}) {
      Long unix = asLong(claims.get(key));
      if (unix != null) {
        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put("unix", unix);
        entry.put("iso", Instant.ofEpochSecond(unix).toString());
        timeClaims.put(key, entry);
      }
    }

    Boolean expired = null;
    Long expiresInSeconds = null;
    Long exp = asLong(claims.get("exp"));
    if (exp != null) {
      expiresInSeconds = exp - now;
      expired = expiresInSeconds <= 0;
    }

    Boolean notYetValid = null;
    Long nbf = asLong(claims.get("nbf"));
    if (nbf != null) {
      notYetValid = nbf > now;
    }

    Map<String, Object> result = new LinkedHashMap<>();
    result.put("header", header);
    result.put("payload", claims);
    result.put("summary", summary);
    result.put("time", timeClaims);
    result.put("expired", expired);
    result.put("expiresInSeconds", expiresInSeconds);
    result.put("notYetValid", notYetValid);
    result.put("evaluatedAt", now);
    return result;
  }

  public static Map<String, Object> inspect(String token) {
    return inspect(token, null);
  }

  private static Long asLong(Object raw) {
    if (raw == null) {
      return null;
    }
    if (raw instanceof Number n) {
      return n.longValue();
    }
    if (raw instanceof String s) {
      try {
        return Long.parseLong(s);
      } catch (NumberFormatException ignored) {
        return null;
      }
    }
    return null;
  }
}
