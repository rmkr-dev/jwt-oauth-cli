package dev.rmkr.jwtoauthcli.http;

import java.io.IOException;

/**
 * Injectable HTTP GET for JWKS documents (test-friendly).
 */
@FunctionalInterface
public interface JwksFetcher {

  String get(String url) throws IOException, InterruptedException;
}
