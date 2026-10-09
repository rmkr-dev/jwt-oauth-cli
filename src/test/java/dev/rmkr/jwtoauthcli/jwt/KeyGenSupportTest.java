package dev.rmkr.jwtoauthcli.jwt;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class KeyGenSupportTest {

  @Test
  void rsaKeyRoundTripsThroughPublicJwks() throws Exception {
    Map<String, Object> out = KeyGenSupport.generate("RS256", "k1", 2048);
    assertEquals("RSA", out.get("kty"));
    assertEquals("k1", out.get("kid"));
    @SuppressWarnings("unchecked")
    RSAKey priv = RSAKey.parse((Map<String, Object>) out.get("jwk"));
    assertTrue(priv.isPrivate());
    @SuppressWarnings("unchecked")
    JWKSet set = JWKSet.parse((Map<String, Object>) out.get("jwks"));
    JWK pub = set.getKeyByKeyId("k1");
    assertFalse(pub.isPrivate());

    SignedJWT jwt = new SignedJWT(
        new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("k1").build(),
        new JWTClaimsSet.Builder().subject("u").build());
    jwt.sign(new RSASSASigner(priv));
    assertTrue(jwt.verify(new RSASSAVerifier(pub.toRSAKey())));
  }

  @Test
  void ecKeyUsesMatchingCurveAndThumbprintKid() throws Exception {
    Map<String, Object> out = KeyGenSupport.generate("es384", null, 2048);
    assertEquals("ES384", out.get("alg"));
    @SuppressWarnings("unchecked")
    ECKey priv = ECKey.parse((Map<String, Object>) out.get("jwk"));
    assertEquals("P-384", priv.getCurve().getName());
    assertEquals(priv.computeThumbprint().toString(), out.get("kid"));

    SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.ES384),
        new JWTClaimsSet.Builder().subject("u").build());
    jwt.sign(new ECDSASigner(priv));
    assertTrue(jwt.verify(new ECDSAVerifier(priv.toPublicJWK())));
  }

  @Test
  void hmacKeyHasNoPublicJwks() {
    Map<String, Object> out = KeyGenSupport.generate("HS512", "h", 2048);
    assertEquals("oct", out.get("kty"));
    assertNull(out.get("jwks"));
    @SuppressWarnings("unchecked")
    Map<String, Object> jwk = (Map<String, Object>) out.get("jwk");
    assertEquals(86, ((String) jwk.get("k")).length()); // 64 bytes base64url
  }

  @Test
  void rejectsWeakRsaAndUnknownAlg() {
    assertThrows(IllegalArgumentException.class, () -> KeyGenSupport.generate("RS256", null, 1024));
    assertThrows(IllegalArgumentException.class, () -> KeyGenSupport.generate("EdDSA", null, 2048));
    assertThrows(IllegalArgumentException.class, () -> KeyGenSupport.generate(" ", null, 2048));
  }
}
