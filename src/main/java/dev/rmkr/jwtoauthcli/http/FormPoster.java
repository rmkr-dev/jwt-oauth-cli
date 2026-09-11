package dev.rmkr.jwtoauthcli.http;

import java.io.IOException;
import java.util.Map;

/**
 * Injectable HTTP poster for form-urlencoded token requests (test-friendly).
 */
@FunctionalInterface
public interface FormPoster {

  HttpResponse post(String url, String formBody, Map<String, String> headers)
      throws IOException, InterruptedException;

  record HttpResponse(int status, boolean ok, String body) {}
}
