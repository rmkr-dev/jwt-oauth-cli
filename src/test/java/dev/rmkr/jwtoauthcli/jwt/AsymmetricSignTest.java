package dev.rmkr.jwtoauthcli.jwt;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;

import com.nimbusds.jose.util.JSONObjectUtils;

import static org.junit.jupiter.api.Assertions.*;

class AsymmetricSignTest {

  @TempDir Path tmp;

  private Path write(String name, Object json) throws Exception {
    @SuppressWarnings("unchecked")
    String body = JSONObjectUtils.toJSONString((Map<String, Object>) json);
    Path p = tmp.resolve(name);
    Files.writeString(p, body);
    return p;
  }

  private Map<String, Object> roundTrip(String alg, String kid) throws Exception {
    Map<String, Object> keys = KeyGenSupport.generate(alg, kid, 2048);
    Path priv = write("priv.json", keys.get("jwk"));
    Path pub = write("jwks.json", keys.get("jwks"));

    Map<String, Object> signOpts = new LinkedHashMap<>();
    signOpts.put("jwkFile", priv.toString());
    signOpts.put("sub", "alice");
    signOpts.put("iss", "https://issuer.example");
    signOpts.put("aud", "api");
    Map<String, Object> signed = JwtSupport.sign(signOpts);

    Map<String, Object> verifyOpts = new LinkedHashMap<>();
    verifyOpts.put("jwksFile", pub.toString());
    verifyOpts.put("iss", "https://issuer.example");
    verifyOpts.put("aud", "api");
    return JwtSupport.verify((String) signed.get("token"), verifyOpts);
  }

  @Test
  void rs256SignsAndVerifiesOffline() throws Exception {
    Map<String, Object> out = roundTrip("RS256", "rsa-1");
    assertEquals(true, out.get("valid"));
    assertEquals("RS256", out.get("algorithm"));
    @SuppressWarnings("unchecked")
    Map<String, Object> header = (Map<String, Object>) out.get("header");
    assertEquals("rsa-1", header.get("kid"));
  }

  @Test
  void ps256SignsAndVerifiesOffline() throws Exception {
    assertEquals("PS256", roundTrip("PS256", "ps-1").get("algorithm"));
  }

  @Test
  void es256SignsAndVerifiesOffline() throws Exception {
    assertEquals("ES256", roundTrip("ES256", "ec-1").get("algorithm"));
  }

  @Test
  void verifyAcceptsSinglePublicJwkFile() throws Exception {
    Map<String, Object> keys = KeyGenSupport.generate("ES256", "ec-2", 2048);
    Path priv = write("priv.json", keys.get("jwk"));
    @SuppressWarnings("unchecked")
    Map<String, Object> jwks = (Map<String, Object>) keys.get("jwks");
    @SuppressWarnings("unchecked")
    Map<String, Object> onlyKey =
        (Map<String, Object>) ((java.util.List<?>) jwks.get("keys")).get(0);
    Path pub = write("pub.json", onlyKey);

    Map<String, Object> signed = JwtSupport.sign(Map.of("jwkFile", priv.toString()));
    Map<String, Object> out =
        JwtSupport.verify((String) signed.get("token"), Map.of("jwksFile", pub.toString()));
    assertEquals(true, out.get("valid"));
  }

  @Test
  void wrongKeyFailsVerification() throws Exception {
    Path priv = write("priv.json", KeyGenSupport.generate("RS256", "k", 2048).get("jwk"));
    Path other = write("other.json", KeyGenSupport.generate("RS256", "k", 2048).get("jwks"));
    Map<String, Object> signed = JwtSupport.sign(Map.of("jwkFile", priv.toString()));
    assertThrows(
        IllegalArgumentException.class,
        () -> JwtSupport.verify((String) signed.get("token"), Map.of("jwksFile", other.toString())));
  }

  @Test
  void publicOnlyJwkCannotSign() throws Exception {
    Path pub = write("jwks.json", KeyGenSupport.generate("RS256", "k", 2048).get("jwks"));
    IllegalArgumentException e =
        assertThrows(
            IllegalArgumentException.class,
            () -> JwtSupport.sign(Map.of("jwkFile", pub.toString())));
    assertTrue(e.getMessage().contains("private"));
  }

  @Test
  void mismatchedAlgIsRejected() throws Exception {
    Path priv = write("priv.json", KeyGenSupport.generate("RS256", "k", 2048).get("jwk"));
    Map<String, Object> opts = new LinkedHashMap<>();
    opts.put("jwkFile", priv.toString());
    opts.put("alg", "ES256");
    opts.put("algExplicit", true);
    assertThrows(IllegalArgumentException.class, () -> JwtSupport.sign(opts));
  }

  @Test
  void secretAndJwkTogetherAreRejected() throws Exception {
    Path priv = write("priv.json", KeyGenSupport.generate("RS256", "k", 2048).get("jwk"));
    Map<String, Object> opts = new LinkedHashMap<>();
    opts.put("jwkFile", priv.toString());
    opts.put("secret", "x".repeat(64));
    assertThrows(IllegalArgumentException.class, () -> JwtSupport.sign(opts));
  }

  @Test
  void multipleVerifySourcesAreRejected() {
    Map<String, Object> opts = new LinkedHashMap<>();
    opts.put("jwksFile", "a.json");
    opts.put("jwksUrl", "https://x");
    assertThrows(
        IllegalArgumentException.class,
        () -> JwtSupport.verify("a.b.c", opts));
  }
}
