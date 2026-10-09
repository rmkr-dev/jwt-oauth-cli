package dev.rmkr.jwtoauthcli.jwt;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.OctetSequenceKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;

import java.util.LinkedHashMap;
import java.util.Map;

/** Generates signing keys as JWKs for local testing of signers and verifiers. */
public final class KeyGenSupport {

  private KeyGenSupport() {}

  /**
   * Generate a signing key.
   *
   * @param alg JWS algorithm (RS256/384/512, PS256/384/512, ES256/384/512, HS256/384/512)
   * @param kid optional key id; when null a SHA-256 thumbprint is used
   * @param rsaBits RSA modulus size (ignored for non-RSA keys), minimum 2048
   * @return map with {@code alg}, {@code kid}, {@code kty}, {@code jwk} (private) and, for
   *     asymmetric keys, {@code publicJwk} and {@code jwks}
   */
  public static Map<String, Object> generate(String alg, String kid, int rsaBits) {
    if (alg == null || alg.isBlank()) {
      throw new IllegalArgumentException("alg is required");
    }
    JWSAlgorithm jwsAlg = JWSAlgorithm.parse(alg.trim().toUpperCase());
    try {
      JWK jwk;
      if (JWSAlgorithm.Family.RSA.contains(jwsAlg)) {
        if (rsaBits < 2048) {
          throw new IllegalArgumentException("RSA key size must be at least 2048 bits");
        }
        var g = (RSAKeyGenerator) new RSAKeyGenerator(rsaBits).keyUse(KeyUse.SIGNATURE).algorithm(jwsAlg);
        jwk = kid == null ? g.keyIDFromThumbprint(true).generate() : g.keyID(kid).generate();
      } else if (JWSAlgorithm.Family.EC.contains(jwsAlg)) {
        Curve curve = curveFor(jwsAlg);
        var g = (ECKeyGenerator) new ECKeyGenerator(curve).keyUse(KeyUse.SIGNATURE).algorithm(jwsAlg);
        jwk = kid == null ? g.keyIDFromThumbprint(true).generate() : g.keyID(kid).generate();
      } else if (JWSAlgorithm.Family.HMAC_SHA.contains(jwsAlg)) {
        int bits = Integer.parseInt(jwsAlg.getName().substring(2));
        var g =
            (OctetSequenceKeyGenerator) new OctetSequenceKeyGenerator(bits).keyUse(KeyUse.SIGNATURE).algorithm(jwsAlg);
        jwk = kid == null ? g.keyIDFromThumbprint(true).generate() : g.keyID(kid).generate();
      } else {
        throw new IllegalArgumentException("Unsupported alg: " + alg);
      }
      Map<String, Object> out = new LinkedHashMap<>();
      out.put("alg", jwsAlg.getName());
      out.put("kty", jwk.getKeyType().getValue());
      out.put("kid", jwk.getKeyID());
      out.put("jwk", jwk.toJSONObject());
      if (jwk.isPrivate() && !"oct".equals(jwk.getKeyType().getValue())) {
        JWK pub = jwk.toPublicJWK();
        out.put("publicJwk", pub.toJSONObject());
        out.put("jwks", new JWKSet(pub).toJSONObject());
      }
      return out;
    } catch (IllegalArgumentException e) {
      throw e;
    } catch (Exception e) {
      throw new IllegalStateException("Key generation failed: " + e.getMessage(), e);
    }
  }

  static Curve curveFor(JWSAlgorithm alg) {
    if (JWSAlgorithm.ES256.equals(alg)) return Curve.P_256;
    if (JWSAlgorithm.ES384.equals(alg)) return Curve.P_384;
    if (JWSAlgorithm.ES512.equals(alg)) return Curve.P_521;
    throw new IllegalArgumentException("Unsupported EC alg: " + alg);
  }
}
