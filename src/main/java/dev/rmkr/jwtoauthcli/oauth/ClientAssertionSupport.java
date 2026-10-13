package dev.rmkr.jwtoauthcli.oauth;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;

/**
 * Client authentication for token-endpoint style requests.
 *
 * <p>Supports {@code client_secret_basic}, {@code client_secret_post}, and the JWT
 * assertion methods from RFC 7523 / OIDC Core section 9: {@code private_key_jwt}
 * (signed with a private RSA/EC JWK) and {@code client_secret_jwt} (HMAC with the
 * client secret). Assertions carry {@code iss = sub = client_id}, {@code aud},
 * a random {@code jti}, {@code iat}, and a short {@code exp}.
 */
public final class ClientAssertionSupport {

  /** RFC 7523 section 2.2 assertion type. */
  public static final String JWT_BEARER_ASSERTION_TYPE =
      "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

  /** Default assertion lifetime in seconds. */
  public static final long DEFAULT_LIFETIME_SECONDS = 60L;

  /** Upper bound on assertion lifetime; these are meant to be short-lived. */
  public static final long MAX_LIFETIME_SECONDS = 3600L;

  /** Client authentication methods understood by the token commands. */
  public enum Method {
    CLIENT_SECRET_BASIC("client_secret_basic"),
    CLIENT_SECRET_POST("client_secret_post"),
    PRIVATE_KEY_JWT("private_key_jwt"),
    CLIENT_SECRET_JWT("client_secret_jwt");

    private final String id;

    Method(String id) {
      this.id = id;
    }

    /** The registered OAuth {@code token_endpoint_auth_method} name. */
    public String id() {
      return id;
    }

    public boolean usesAssertion() {
      return this == PRIVATE_KEY_JWT || this == CLIENT_SECRET_JWT;
    }

    public boolean needsSecret() {
      return this != PRIVATE_KEY_JWT;
    }

    /**
     * Parse {@code basic|post|private_key_jwt|client_secret_jwt}; the full
     * registered names ({@code client_secret_basic}, {@code client_secret_post})
     * and hyphenated spellings are accepted too. Returns {@code null} for blank input.
     */
    public static Method parse(String raw) {
      if (raw == null || raw.isBlank()) {
        return null;
      }
      String v = raw.trim().toLowerCase(Locale.ROOT).replace('-', '_');
      return switch (v) {
        case "basic", "client_secret_basic" -> CLIENT_SECRET_BASIC;
        case "post", "client_secret_post" -> CLIENT_SECRET_POST;
        case "private_key_jwt" -> PRIVATE_KEY_JWT;
        case "client_secret_jwt" -> CLIENT_SECRET_JWT;
        default ->
            throw new IllegalArgumentException(
                "Unsupported client auth '"
                    + raw
                    + "' (expected basic, post, private_key_jwt, or client_secret_jwt)");
      };
    }
  }

  private ClientAssertionSupport() {}

  /**
   * Build a signed client assertion.
   *
   * <p>Options:
   *
   * <ul>
   *   <li>{@code clientId} (required) - used for {@code iss} and {@code sub}
   *   <li>{@code audience} (required) - {@code aud}, normally the token endpoint
   *   <li>{@code method} - {@code private_key_jwt} (default when a JWK is given) or
   *       {@code client_secret_jwt}
   *   <li>{@code clientJwk} / {@code clientJwkFile} - private JWK JSON or file path
   *       (single JWK, or a JWKS with exactly one private key)
   *   <li>{@code clientSecret} - HMAC key for {@code client_secret_jwt}
   *   <li>{@code alg} - JWS algorithm; defaults to the JWK's alg (else RS256 or the
   *       curve's ES*), or HS256 for {@code client_secret_jwt}
   *   <li>{@code lifetimeSeconds} - {@code exp - iat} (default 60)
   *   <li>{@code now} - epoch seconds override for {@code iat} (tests)
   *   <li>{@code jti} - fixed {@code jti} (tests); random UUID otherwise
   * </ul>
   *
   * @return map with {@code client_assertion_type}, {@code client_assertion},
   *     {@code header}, and {@code payload}
   */
  public static Map<String, Object> buildAssertion(Map<String, Object> options) {
    Map<String, Object> opts = options != null ? options : Map.of();
    String clientId = requireString(opts, "clientId");
    String audience = requireString(opts, "audience");
    String jwkJson = loadJwkJson(opts);
    String secret = asNullableString(opts.get("clientSecret"));

    Method method = Method.parse(asNullableString(opts.get("method")));
    if (method == null) {
      method = jwkJson != null ? Method.PRIVATE_KEY_JWT : Method.CLIENT_SECRET_JWT;
    }
    if (!method.usesAssertion()) {
      throw new IllegalArgumentException(
          method.id() + " does not use a client assertion (use private_key_jwt or client_secret_jwt)");
    }

    long lifetime = lifetimeSeconds(opts.get("lifetimeSeconds"));
    long now = opts.get("now") instanceof Number n ? n.longValue() : System.currentTimeMillis() / 1000L;
    String jti = asNullableString(opts.get("jti"));
    if (jti == null || jti.isEmpty()) {
      jti = UUID.randomUUID().toString();
    }
    String algName = asNullableString(opts.get("alg"));

    JWSAlgorithm alg;
    JWSSigner signer;
    String kid = null;
    if (method == Method.PRIVATE_KEY_JWT) {
      if (jwkJson == null) {
        throw new IllegalArgumentException(
            "private_key_jwt requires a private JWK (pass --client-jwk-file)");
      }
      JWK jwk = selectPrivateKey(jwkJson);
      alg = resolveAsymmetricAlg(jwk, algName);
      signer = asymmetricSigner(jwk);
      kid = jwk.getKeyID();
    } else {
      if (secret == null || secret.isEmpty()) {
        throw new IllegalArgumentException(
            "client_secret_jwt requires a client secret (pass --client-secret or set JWT_OAUTH_CLIENT_SECRET)");
      }
      alg = JWSAlgorithm.parse(algName == null || algName.isEmpty() ? "HS256" : algName.trim());
      if (!JWSAlgorithm.Family.HMAC_SHA.contains(alg)) {
        throw new IllegalArgumentException(
            "client_secret_jwt needs an HMAC algorithm (HS256/HS384/HS512), got " + alg.getName());
      }
      signer = hmacSigner(secret, alg);
    }

    JWTClaimsSet claims =
        new JWTClaimsSet.Builder()
            .issuer(clientId)
            .subject(clientId)
            .audience(audience)
            .jwtID(jti)
            .issueTime(new Date(now * 1000L))
            .expirationTime(new Date((now + lifetime) * 1000L))
            .build();

    JWSHeader.Builder hb = new JWSHeader.Builder(alg).type(JOSEObjectType.JWT);
    if (kid != null && !kid.isEmpty()) {
      hb.keyID(kid);
    }
    JWSHeader header = hb.build();

    SignedJWT jwt = new SignedJWT(header, claims);
    try {
      jwt.sign(signer);
    } catch (JOSEException e) {
      throw new IllegalArgumentException("Failed to sign client assertion: " + e.getMessage(), e);
    }

    Map<String, Object> out = new LinkedHashMap<>();
    out.put("client_assertion_type", JWT_BEARER_ASSERTION_TYPE);
    out.put("client_assertion", jwt.serialize());
    out.put("header", new LinkedHashMap<>(header.toJSONObject()));
    out.put("payload", new LinkedHashMap<>(claims.toJSONObject()));
    return out;
  }

  /**
   * Apply client authentication to an outgoing form request.
   *
   * <p>The caller has already put {@code client_id} (and {@code client_secret} when
   * one was supplied) into {@code body}, which is exactly the historical behaviour
   * and stays untouched when {@code params.clientAuth} is absent. Otherwise:
   *
   * <ul>
   *   <li>{@code post}: secret required, stays in the body
   *   <li>{@code basic}: secret moves to an {@code Authorization: Basic} header
   *   <li>{@code private_key_jwt} / {@code client_secret_jwt}: secret is removed and
   *       {@code client_assertion_type} + {@code client_assertion} are added
   * </ul>
   *
   * @param defaultAudience assertion {@code aud} unless {@code params.assertionAudience} is set
   */
  static void apply(
      Map<String, Object> params,
      String defaultAudience,
      Map<String, String> body,
      Map<String, String> headers) {
    Method method = Method.parse(asNullableString(params.get("clientAuth")));
    String clientId = asNullableString(params.get("clientId"));
    String secret = asNullableString(params.get("clientSecret"));
    boolean hasSecret = secret != null && !secret.isEmpty();
    boolean hasJwk = hasText(params.get("clientJwk")) || hasText(params.get("clientJwkFile"));

    if (method == null) {
      if (hasJwk) {
        throw new IllegalArgumentException(
            "--client-jwk-file is only used with --client-auth private_key_jwt");
      }
      return;
    }
    if (method != Method.PRIVATE_KEY_JWT && hasJwk) {
      throw new IllegalArgumentException(
          "--client-jwk-file is only used with --client-auth private_key_jwt");
    }
    if (method.needsSecret() && !hasSecret) {
      throw new IllegalArgumentException(
          method.id()
              + " requires a client secret (pass --client-secret or set JWT_OAUTH_CLIENT_SECRET)");
    }

    switch (method) {
      case CLIENT_SECRET_POST -> body.put("client_secret", secret);
      case CLIENT_SECRET_BASIC -> {
        body.remove("client_secret");
        headers.put("authorization", basicAuthorization(clientId, secret));
      }
      case PRIVATE_KEY_JWT, CLIENT_SECRET_JWT -> {
        body.remove("client_secret");
        String aud = asNullableString(params.get("assertionAudience"));
        Map<String, Object> opts = new LinkedHashMap<>();
        opts.put("clientId", clientId);
        opts.put("audience", aud != null && !aud.isEmpty() ? aud : defaultAudience);
        opts.put("method", method.id());
        opts.put("clientJwk", params.get("clientJwk"));
        opts.put("clientJwkFile", params.get("clientJwkFile"));
        opts.put("clientSecret", method == Method.CLIENT_SECRET_JWT ? secret : null);
        opts.put("alg", params.get("assertionAlg"));
        opts.put("lifetimeSeconds", params.get("assertionLifetimeSeconds"));
        opts.put("now", params.get("assertionNow"));
        Map<String, Object> assertion = buildAssertion(opts);
        body.put("client_assertion_type", JWT_BEARER_ASSERTION_TYPE);
        body.put("client_assertion", String.valueOf(assertion.get("client_assertion")));
      }
      default -> throw new IllegalStateException("unreachable");
    }
  }

  /** Whether the given {@code clientAuth} value needs a client secret (default mode does not). */
  public static boolean requiresSecret(String clientAuth) {
    Method m = Method.parse(clientAuth);
    return m != null && m.needsSecret();
  }

  /** RFC 6749 section 2.3.1: form-encode id and secret, then Base64 {@code id:secret}. */
  static String basicAuthorization(String clientId, String secret) {
    String pair = formEncode(clientId) + ":" + formEncode(secret);
    return "Basic " + Base64.getEncoder().encodeToString(pair.getBytes(StandardCharsets.UTF_8));
  }

  private static String formEncode(String s) {
    return URLEncoder.encode(s == null ? "" : s, StandardCharsets.UTF_8);
  }

  private static String loadJwkJson(Map<String, Object> opts) {
    String inline = asNullableString(opts.get("clientJwk"));
    if (inline != null && !inline.isBlank()) {
      return inline;
    }
    String file = asNullableString(opts.get("clientJwkFile"));
    if (file == null || file.isBlank()) {
      return null;
    }
    try {
      return Files.readString(Path.of(file), StandardCharsets.UTF_8);
    } catch (IOException e) {
      throw new IllegalArgumentException("Cannot read client JWK file: " + file, e);
    }
  }

  private static JWK selectPrivateKey(String json) {
    JWKSet set;
    try {
      Map<String, Object> parsed = JSONObjectUtils.parse(json);
      set = parsed.containsKey("keys") ? JWKSet.parse(parsed) : new JWKSet(JWK.parse(parsed));
    } catch (Exception e) {
      throw new IllegalArgumentException("Invalid client JWK: " + e.getMessage(), e);
    }
    List<JWK> privates = new ArrayList<>();
    for (JWK k : set.getKeys()) {
      if (k.isPrivate() && (k instanceof RSAKey || k instanceof ECKey)) {
        privates.add(k);
      }
    }
    if (privates.size() != 1) {
      throw new IllegalArgumentException(
          "Client JWK must contain exactly one private RSA or EC key (found "
              + privates.size()
              + ")");
    }
    return privates.get(0);
  }

  private static JWSAlgorithm resolveAsymmetricAlg(JWK jwk, String requested) {
    String name = requested;
    if (name == null || name.isBlank()) {
      if (jwk.getAlgorithm() != null) {
        name = jwk.getAlgorithm().getName();
      } else if (jwk instanceof RSAKey) {
        name = "RS256";
      } else {
        String crv = ((ECKey) jwk).getCurve() != null ? ((ECKey) jwk).getCurve().getName() : "";
        name =
            switch (crv) {
              case "P-384" -> "ES384";
              case "P-521" -> "ES512";
              case "secp256k1" -> "ES256K";
              default -> "ES256";
            };
      }
    }
    JWSAlgorithm alg = JWSAlgorithm.parse(name.trim());
    if (jwk instanceof RSAKey && !JWSAlgorithm.Family.RSA.contains(alg)) {
      throw new IllegalArgumentException(
          "Algorithm " + alg.getName() + " does not match RSA client key (use RS* or PS*)");
    }
    if (jwk instanceof ECKey ec) {
      if (!JWSAlgorithm.Family.EC.contains(alg)) {
        throw new IllegalArgumentException(
            "Algorithm " + alg.getName() + " does not match EC client key (use ES*)");
      }
      if (ec.getCurve() != null) {
        boolean curveOk =
            com.nimbusds.jose.jwk.Curve.forJWSAlgorithm(alg).contains(ec.getCurve());
        if (!curveOk) {
          throw new IllegalArgumentException(
              "Algorithm " + alg.getName() + " does not match curve " + ec.getCurve().getName());
        }
      }
    }
    return alg;
  }

  private static JWSSigner asymmetricSigner(JWK jwk) {
    try {
      if (jwk instanceof RSAKey rsa) {
        return new RSASSASigner(rsa);
      }
      return new ECDSASigner((ECKey) jwk);
    } catch (JOSEException e) {
      throw new IllegalArgumentException("Unusable client JWK: " + e.getMessage(), e);
    }
  }

  private static JWSSigner hmacSigner(String secret, JWSAlgorithm alg) {
    byte[] key = secret.getBytes(StandardCharsets.UTF_8);
    int minBytes =
        alg.equals(JWSAlgorithm.HS256) ? 32 : alg.equals(JWSAlgorithm.HS384) ? 48 : 64;
    if (key.length < minBytes) {
      throw new IllegalArgumentException(
          "Client secret too short for "
              + alg.getName()
              + ": need at least "
              + minBytes
              + " bytes, got "
              + key.length);
    }
    try {
      return new MACSigner(key);
    } catch (JOSEException e) {
      throw new IllegalArgumentException("Unusable client secret: " + e.getMessage(), e);
    }
  }

  private static long lifetimeSeconds(Object raw) {
    if (raw == null || (raw instanceof String s && s.isBlank())) {
      return DEFAULT_LIFETIME_SECONDS;
    }
    long v;
    try {
      v = raw instanceof Number n ? n.longValue() : Long.parseLong(String.valueOf(raw).trim());
    } catch (NumberFormatException e) {
      throw new IllegalArgumentException("assertion lifetime must be a whole number of seconds");
    }
    if (v <= 0 || v > MAX_LIFETIME_SECONDS) {
      throw new IllegalArgumentException(
          "assertion lifetime must be between 1 and " + MAX_LIFETIME_SECONDS + " seconds");
    }
    return v;
  }

  private static boolean hasText(Object v) {
    return v != null && !String.valueOf(v).isBlank();
  }

  private static String requireString(Map<String, Object> params, String key) {
    Object v = params.get(key);
    if (!(v instanceof String s) || s.isEmpty()) {
      throw new IllegalArgumentException(key + " is required");
    }
    return s;
  }

  private static String asNullableString(Object v) {
    return v == null ? null : String.valueOf(v);
  }
}
