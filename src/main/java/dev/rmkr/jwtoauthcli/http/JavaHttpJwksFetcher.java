package dev.rmkr.jwtoauthcli.http;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/** Default {@link JwksFetcher} backed by {@link HttpClient}. */
public final class JavaHttpJwksFetcher implements JwksFetcher {

  private final HttpClient client;

  public JavaHttpJwksFetcher() {
    this(
        HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(30))
            .followRedirects(HttpClient.Redirect.NEVER)
            .build());
  }

  public JavaHttpJwksFetcher(HttpClient client) {
    this.client = client;
  }

  @Override
  public String get(String url) throws IOException, InterruptedException {
    HttpRequest request =
        HttpRequest.newBuilder()
            .uri(URI.create(url))
            .timeout(Duration.ofSeconds(60))
            .header("accept", "application/json")
            .GET()
            .build();
    HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
    int status = response.statusCode();
    if (status < 200 || status >= 300) {
      throw new IOException("JWKS fetch failed: HTTP " + status);
    }
    return response.body() == null ? "" : response.body();
  }
}
