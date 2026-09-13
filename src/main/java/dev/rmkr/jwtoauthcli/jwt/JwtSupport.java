package dev.rmkr.jwtoauthcli.jwt;

import com.nimbusds.jose.Header;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import dev.rmkr.jwtoauthcli.http.JavaHttpJwksFetcher;
import dev.rmkr.jwtoauthcli.http.JwksFetcher;

import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * JWT decode, inspect, and verify helpers.
 * Uses Nimbus JOSE+JWT for header/claims parsing and signature verification
 * (HMAC via shared secret, or RS/ES algorithms via JWKS).
 */
public final class JwtSupport {

  private static final JwksFetcher DEFAULT_JWKS_FETCHER = new JavaHttpJwksFetcher();
  private static final long DEFAULT_EXP_LEEWAY_SECONDS = 60L;

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

  /**
   * Verify a signed JWT (HMAC via {@code secret}, or RS/ES algorithms via {@code jwksUrl}).
   *
   * <p>Supported options (Map keys):
   * <ul>
   *   <li>{@code secret} - HMAC shared secret (HS256/HS384/HS512)</li>
   *   <li>{@code jwksUrl} - JWKS URL for public-key algorithms</li>
   *   <li>{@code jwksFetcher} - optional {@link JwksFetcher} (defaults to HTTP GET)</li>
   *   <li>{@code iss} - expected issuer (optional)</li>
   *   <li>{@code aud} - expected audience (optional)</li>
   *   <li>{@code expLeewaySeconds} - clock skew for exp (default 60)</li>
   *   <li>{@code nowSec} - evaluation time override for tests</li>
   * </ul>
   *
   * @return map with {@code valid}, {@code header}, {@code payload},
   *     {@code claimsChecked}, {@code algorithm}
   */
  public static Map<String, Object> verify(String token, Map<String, Object> options) {
    if (token == null || token.trim().isEmpty()) {
      throw new IllegalArgumentException("JWT token must be a non-empty string");
    }
    Map<String, Object> opts = options != null ? options : Map.of();

    String secret = asNullableString(opts.get("secret"));
    String jwksUrl = asNullableString(opts.get("jwksUrl"));
    boolean hasSecret = secret != null && !secret.isEmpty();
    boolean hasJwks = jwksUrl != null && !jwksUrl.isEmpty();
    if (hasSecret == hasJwks) {
      throw new IllegalArgumentException(
          "Provide exactly one of --secret (or JWT_OAUTH_HMAC_SECRET) or --jwks-url");
    }

    SignedJWT signed;
    try {
      signed = SignedJWT.parse(token.trim());
    } catch (ParseException e) {
      throw new IllegalArgumentException("Failed to parse JWT: " + e.getMessage(), e);
    }

    JWSHeader jwsHeader = signed.getHeader();
    JWSAlgorithm alg = jwsHeader.getAlgorithm();
    if (alg == null) {
      throw new IllegalArgumentException("JWT header missing alg");
    }

    try {
      JWSVerifier verifier;
      if (hasSecret) {
        verifier = hmacVerifier(alg, secret);
      } else {
        verifier = jwksVerifier(alg, jwsHeader, jwksUrl, opts);
      }

      if (!signed.verify(verifier)) {
        throw new IllegalArgumentException("JWT signature verification failed");
      }
    } catch (JOSEException e) {
      throw new IllegalArgumentException("JWT signature verification failed: " + e.getMessage(), e);
    }

    JWTClaimsSet claims;
    try {
      claims = signed.getJWTClaimsSet();
    } catch (ParseException e) {
      throw new IllegalArgumentException("Failed to parse JWT claims: " + e.getMessage(), e);
    }

    long leeway = DEFAULT_EXP_LEEWAY_SECONDS;
    Object leewayRaw = opts.get("expLeewaySeconds");
    if (leewayRaw instanceof Number n) {
      leeway = n.longValue();
    } else if (leewayRaw instanceof String s && !s.isEmpty()) {
      try {
        leeway = Long.parseLong(s);
      } catch (NumberFormatException e) {
        throw new IllegalArgumentException("expLeewaySeconds must be a number", e);
      }
    }
    if (leeway < 0) {
      throw new IllegalArgumentException("expLeewaySeconds must be >= 0");
    }

    Long nowSec = asLong(opts.get("nowSec"));
    long now = nowSec != null ? nowSec : Instant.now().getEpochSecond();

    Map<String, Object> claimsChecked = new LinkedHashMap<>();
    checkExpiration(claims, now, leeway, claimsChecked);

    String expectedIss = asNullableString(opts.get("iss"));
    if (expectedIss != null && !expectedIss.isEmpty()) {
      String actualIss = claims.getIssuer();
      if (actualIss == null || !expectedIss.equals(actualIss)) {
        throw new IllegalArgumentException(
            "Issuer claim mismatch: expected " + expectedIss + ", got " + actualIss);
      }
      claimsChecked.put("iss", expectedIss);
    }

    String expectedAud = asNullableString(opts.get("aud"));
    if (expectedAud != null && !expectedAud.isEmpty()) {
      List<String> audiences = claims.getAudience();
      if (audiences == null || !audiences.contains(expectedAud)) {
        throw new IllegalArgumentException(
            "Audience claim mismatch: expected " + expectedAud + ", got " + audiences);
      }
      claimsChecked.put("aud", expectedAud);
    }

    Map<String, Object> result = new LinkedHashMap<>();
    result.put("valid", true);
    result.put("header", new LinkedHashMap<>(jwsHeader.toJSONObject()));
    result.put("payload", new LinkedHashMap<>(claims.toJSONObject()));
    result.put("claimsChecked", claimsChecked);
    result.put("algorithm", alg.getName());
    return result;
  }

  private static JWSVerifier hmacVerifier(JWSAlgorithm alg, String secret) throws JOSEException {
    if (!JWSAlgorithm.Family.HMAC_SHA.contains(alg)) {
      throw new IllegalArgumentException(
          "HMAC secret provided but algorithm is "
              + alg.getName()
              + " (expected HS256/HS384/HS512)");
    }
    byte[] keyBytes = secret.getBytes(StandardCharsets.UTF_8);
    return new MACVerifier(keyBytes);
  }

  private static JWSVerifier jwksVerifier(
      JWSAlgorithm alg, JWSHeader header, String jwksUrl, Map<String, Object> opts)
      throws JOSEException {
    if (JWSAlgorithm.Family.HMAC_SHA.contains(alg)) {
      throw new IllegalArgumentException(
          "JWKS URL provided but algorithm is "
              + alg.getName()
              + " (use --secret for HMAC)");
    }

    JwksFetcher fetcher = DEFAULT_JWKS_FETCHER;
    Object custom = opts.get("jwksFetcher");
    if (custom instanceof JwksFetcher jf) {
      fetcher = jf;
    }

    String body;
    try {
      body = fetcher.get(jwksUrl);
    } catch (Exception e) {
      throw new IllegalArgumentException(
          "Failed to fetch JWKS from " + jwksUrl + ": " + e.getMessage(), e);
    }

    JWKSet jwkSet;
    try {
      jwkSet = JWKSet.parse(body);
    } catch (ParseException e) {
      throw new IllegalArgumentException("Invalid JWKS document: " + e.getMessage(), e);
    }

    JWKMatcher.Builder matcher =
        new JWKMatcher.Builder().keyUse(com.nimbusds.jose.jwk.KeyUse.SIGNATURE).algorithm(alg);
    if (header.getKeyID() != null) {
      matcher.keyID(header.getKeyID());
    }
    if (JWSAlgorithm.Family.RSA.contains(alg)) {
      matcher.keyType(KeyType.RSA);
    } else if (JWSAlgorithm.Family.EC.contains(alg)) {
      matcher.keyType(KeyType.EC);
    }

    List<JWK> matches = new JWKSelector(matcher.build()).select(jwkSet);
    if (matches.isEmpty() && header.getKeyID() != null) {
      JWKMatcher.Builder fallback =
          new JWKMatcher.Builder().keyID(header.getKeyID()).algorithm(alg);
      if (JWSAlgorithm.Family.RSA.contains(alg)) {
        fallback.keyType(KeyType.RSA);
      } else if (JWSAlgorithm.Family.EC.contains(alg)) {
        fallback.keyType(KeyType.EC);
      }
      matches = new JWKSelector(fallback.build()).select(jwkSet);
    }
    if (matches.isEmpty()) {
      // Last resort: kid only (some JWKS omit alg/use).
      if (header.getKeyID() != null) {
        matches =
            new JWKSelector(new JWKMatcher.Builder().keyID(header.getKeyID()).build())
                .select(jwkSet);
      }
    }
    if (matches.isEmpty()) {
      throw new IllegalArgumentException(
          "No matching JWK found for kid="
              + header.getKeyID()
              + " alg="
              + alg.getName());
    }

    JWK jwk = matches.get(0);
    if (jwk instanceof RSAKey rsa) {
      return new RSASSAVerifier(rsa.toRSAPublicKey());
    }
    if (jwk instanceof ECKey ec) {
      return new ECDSAVerifier(ec.toECPublicKey());
    }
    throw new IllegalArgumentException("Unsupported JWK key type: " + jwk.getKeyType());
  }

  private static void checkExpiration(
      JWTClaimsSet claims, long now, long leeway, Map<String, Object> claimsChecked) {
    Long exp = null;
    if (claims.getExpirationTime() != null) {
      exp = claims.getExpirationTime().toInstant().getEpochSecond();
    }
    if (exp == null) {
      exp = asLong(claims.getClaim("exp"));
    }
    if (exp != null) {
      if (now > exp + leeway) {
        throw new IllegalArgumentException(
            "JWT expired (exp=" + exp + ", now=" + now + ", leeway=" + leeway + ")");
      }
      Map<String, Object> expCheck = new LinkedHashMap<>();
      expCheck.put("exp", exp);
      expCheck.put("leewaySeconds", leeway);
      claimsChecked.put("exp", expCheck);
    }
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

  private static String asNullableString(Object v) {
    return v == null ? null : String.valueOf(v);
  }
}
