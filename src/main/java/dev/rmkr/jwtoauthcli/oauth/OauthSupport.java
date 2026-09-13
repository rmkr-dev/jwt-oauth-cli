package dev.rmkr.jwtoauthcli.oauth;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.rmkr.jwtoauthcli.http.FormPoster;
import dev.rmkr.jwtoauthcli.http.JavaHttpFormPoster;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.StringJoiner;

/**
 * OAuth 2.0 helpers: authorize URL construction, local code exchange,
 * PKCE generation, refresh-token grant, and client-credentials grant.
 */
public final class OauthSupport {

  private static final ObjectMapper MAPPER = new ObjectMapper();
  private static final SecureRandom SECURE_RANDOM = new SecureRandom();
  private static final FormPoster DEFAULT_POSTER = new JavaHttpFormPoster();

  private OauthSupport() {}

  public static String buildAuthorizeUrl(Map<String, Object> params) {
    String authorizationEndpoint = requireString(params, "authorizationEndpoint");
    String clientId = requireString(params, "clientId");
    String redirectUri = requireString(params, "redirectUri");
    String responseType = stringOrDefault(params.get("responseType"), "code");
    Object scope = params.get("scope");
    String state = asNullableString(params.get("state"));
    String codeChallenge = asNullableString(params.get("codeChallenge"));
    String codeChallengeMethod = asNullableString(params.get("codeChallengeMethod"));
    @SuppressWarnings("unchecked")
    Map<String, Object> extra =
        params.get("extra") instanceof Map
            ? (Map<String, Object>) params.get("extra")
            : Map.of();

    URI base;
    try {
      base = URI.create(authorizationEndpoint);
      if (base.getScheme() == null || base.getHost() == null) {
        throw new IllegalArgumentException("authorizationEndpoint must be a valid URL");
      }
    } catch (IllegalArgumentException e) {
      throw new IllegalArgumentException("authorizationEndpoint must be a valid URL", e);
    }

    Map<String, String> query = new LinkedHashMap<>();
    // Preserve any existing query params from the endpoint.
    String existing = base.getRawQuery();
    if (existing != null && !existing.isEmpty()) {
      for (String pair : existing.split("&")) {
        int eq = pair.indexOf('=');
        if (eq < 0) {
          query.put(decode(pair), "");
        } else {
          query.put(decode(pair.substring(0, eq)), decode(pair.substring(eq + 1)));
        }
      }
    }

    query.put("response_type", responseType);
    query.put("client_id", clientId);
    query.put("redirect_uri", redirectUri);

    if (scope != null && !(scope instanceof String s && s.isEmpty())) {
      query.put("scope", joinScope(scope));
    }
    if (state != null && !state.isEmpty()) {
      query.put("state", state);
    }
    if (codeChallenge != null && !codeChallenge.isEmpty()) {
      query.put("code_challenge", codeChallenge);
      query.put(
          "code_challenge_method",
          codeChallengeMethod != null && !codeChallengeMethod.isEmpty()
              ? codeChallengeMethod
              : "S256");
    }

    for (Map.Entry<String, Object> e : extra.entrySet()) {
      if (e.getValue() != null) {
        query.put(e.getKey(), String.valueOf(e.getValue()));
      }
    }

    StringBuilder sb = new StringBuilder();
    sb.append(schemeHostPath(base));
    sb.append('?');
    boolean first = true;
    for (Map.Entry<String, String> e : query.entrySet()) {
      if (!first) {
        sb.append('&');
      }
      first = false;
      sb.append(encode(e.getKey())).append('=').append(encode(e.getValue()));
    }
    return sb.toString();
  }

  public static Map<String, Object> exchangeCode(Map<String, Object> params) throws Exception {
    return exchangeCode(params, DEFAULT_POSTER);
  }

  public static Map<String, Object> exchangeCode(Map<String, Object> params, FormPoster poster)
      throws Exception {
    String tokenEndpoint = requireString(params, "tokenEndpoint");
    String code = requireString(params, "code");
    String redirectUri = requireString(params, "redirectUri");
    String clientId = requireString(params, "clientId");
    String clientSecret = asNullableString(params.get("clientSecret"));
    String codeVerifier = asNullableString(params.get("codeVerifier"));
    String grantType = stringOrDefault(params.get("grantType"), "authorization_code");

    validateUrl(tokenEndpoint, "tokenEndpoint");

    Map<String, String> body = new LinkedHashMap<>();
    body.put("grant_type", grantType);
    body.put("code", code);
    body.put("redirect_uri", redirectUri);
    body.put("client_id", clientId);
    if (clientSecret != null && !clientSecret.isEmpty()) {
      body.put("client_secret", clientSecret);
    }
    if (codeVerifier != null && !codeVerifier.isEmpty()) {
      body.put("code_verifier", codeVerifier);
    }

    return postToken(tokenEndpoint, body, poster, "Token exchange failed");
  }

  public static Map<String, Object> generatePkce() {
    return generatePkce(32);
  }

  public static Map<String, Object> generatePkce(int verifierBytes) {
    if (verifierBytes < 32 || verifierBytes > 96) {
      throw new IllegalArgumentException("verifierBytes must be an integer between 32 and 96");
    }
    byte[] raw = new byte[verifierBytes];
    SECURE_RANDOM.nextBytes(raw);
    String codeVerifier = base64UrlEncode(raw);
    if (codeVerifier.length() < 43 || codeVerifier.length() > 128) {
      throw new IllegalStateException("generated code_verifier length outside RFC 7636 range");
    }

    byte[] digest;
    try {
      digest = MessageDigest.getInstance("SHA-256").digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 not available", e);
    }
    String codeChallenge = base64UrlEncode(digest);

    byte[] stateRaw = new byte[16];
    SECURE_RANDOM.nextBytes(stateRaw);
    String state = base64UrlEncode(stateRaw);

    Map<String, Object> result = new LinkedHashMap<>();
    result.put("code_verifier", codeVerifier);
    result.put("code_challenge", codeChallenge);
    result.put("code_challenge_method", "S256");
    result.put("state", state);
    return result;
  }

  public static Map<String, Object> refreshToken(Map<String, Object> params) throws Exception {
    return refreshToken(params, DEFAULT_POSTER);
  }

  public static Map<String, Object> refreshToken(Map<String, Object> params, FormPoster poster)
      throws Exception {
    String tokenEndpoint = requireString(params, "tokenEndpoint");
    String refreshTokenValue = requireString(params, "refreshToken");
    String clientId = requireString(params, "clientId");
    String clientSecret = asNullableString(params.get("clientSecret"));
    Object scope = params.get("scope");

    validateUrl(tokenEndpoint, "tokenEndpoint");

    Map<String, String> body = new LinkedHashMap<>();
    body.put("grant_type", "refresh_token");
    body.put("refresh_token", refreshTokenValue);
    body.put("client_id", clientId);
    if (clientSecret != null && !clientSecret.isEmpty()) {
      body.put("client_secret", clientSecret);
    }
    if (scope != null && !(scope instanceof String s && s.isEmpty())) {
      body.put("scope", joinScope(scope));
    }

    return postToken(tokenEndpoint, body, poster, "Token refresh failed");
  }


  public static Map<String, Object> clientCredentials(Map<String, Object> params) throws Exception {
    return clientCredentials(params, DEFAULT_POSTER);
  }

  public static Map<String, Object> clientCredentials(Map<String, Object> params, FormPoster poster)
      throws Exception {
    String tokenEndpoint = requireString(params, "tokenEndpoint");
    String clientId = requireString(params, "clientId");
    String clientSecret = requireString(params, "clientSecret");
    Object scope = params.get("scope");

    validateUrl(tokenEndpoint, "tokenEndpoint");

    Map<String, String> body = new LinkedHashMap<>();
    body.put("grant_type", "client_credentials");
    body.put("client_id", clientId);
    body.put("client_secret", clientSecret);
    if (scope != null && !(scope instanceof String s && s.isEmpty())) {
      body.put("scope", joinScope(scope));
    }

    return postToken(tokenEndpoint, body, poster, "Client credentials grant failed");
  }

  private static Map<String, Object> postToken(
      String tokenEndpoint, Map<String, String> body, FormPoster poster, String failPrefix)
      throws Exception {
    String form = encodeForm(body);
    Map<String, String> headers = new LinkedHashMap<>();
    headers.put("content-type", "application/x-www-form-urlencoded");
    headers.put("accept", "application/json");

    FormPoster.HttpResponse response = poster.post(tokenEndpoint, form, headers);
    String text = response.body() == null ? "" : response.body();

    Map<String, Object> data;
    try {
      if (text.isBlank()) {
        data = new LinkedHashMap<>();
      } else {
        data = MAPPER.readValue(text, new TypeReference<LinkedHashMap<String, Object>>() {});
      }
    } catch (Exception e) {
      String snippet = text.length() > 200 ? text.substring(0, 200) : text;
      throw new IllegalStateException(
          "Token endpoint returned non-JSON (HTTP " + response.status() + "): " + snippet, e);
    }

    if (!response.ok()) {
      Object desc = data.get("error_description");
      Object err = data.get("error");
      String errMsg =
          desc != null
              ? String.valueOf(desc)
              : (err != null ? String.valueOf(err) : ("HTTP " + response.status()));
      throw new IllegalStateException(failPrefix + ": " + errMsg);
    }
    return data;
  }

  private static String encodeForm(Map<String, String> body) {
    StringJoiner joiner = new StringJoiner("&");
    for (Map.Entry<String, String> e : body.entrySet()) {
      joiner.add(encode(e.getKey()) + "=" + encode(e.getValue()));
    }
    return joiner.toString();
  }

  private static String joinScope(Object scope) {
    if (scope instanceof Collection<?> c) {
      StringJoiner j = new StringJoiner(" ");
      for (Object o : c) {
        j.add(String.valueOf(o));
      }
      return j.toString();
    }
    return String.valueOf(scope);
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

  private static String stringOrDefault(Object v, String def) {
    if (v == null) {
      return def;
    }
    String s = String.valueOf(v);
    return s.isEmpty() ? def : s;
  }

  private static void validateUrl(String url, String name) {
    try {
      URI u = URI.create(url);
      if (u.getScheme() == null || u.getHost() == null) {
        throw new IllegalArgumentException(name + " must be a valid URL");
      }
    } catch (IllegalArgumentException e) {
      throw new IllegalArgumentException(name + " must be a valid URL", e);
    }
  }

  private static String schemeHostPath(URI base) {
    StringBuilder sb = new StringBuilder();
    sb.append(base.getScheme()).append("://").append(base.getRawAuthority());
    String path = base.getRawPath();
    sb.append(path == null || path.isEmpty() ? "/" : path);
    return sb.toString();
  }

  private static String encode(String s) {
    return URLEncoder.encode(s, StandardCharsets.UTF_8).replace("+", "%20");
  }

  private static String decode(String s) {
    return java.net.URLDecoder.decode(s, StandardCharsets.UTF_8);
  }

  static String base64UrlEncode(byte[] buf) {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(buf);
  }
}
