package dev.rmkr.jwtoauthcli.http;

import java.io.IOException;
import java.util.Map;

/**
 * Injectable HTTP GET for JSON metadata / UserInfo requests (test-friendly).
 */
@FunctionalInterface
public interface JsonGetClient {

  FormPoster.HttpResponse get(String url, Map<String, String> headers)
      throws IOException, InterruptedException;
}
