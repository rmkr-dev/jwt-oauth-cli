package dev.rmkr.jwtoauthcli.http;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;

/** Default {@link JsonGetClient} backed by {@link HttpClient}. */
public final class JavaHttpJsonGetClient implements JsonGetClient {

  private final HttpClient client;

  public JavaHttpJsonGetClient() {
    this(
        HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(30))
            .followRedirects(HttpClient.Redirect.NEVER)
            .build());
  }

  public JavaHttpJsonGetClient(HttpClient client) {
    this.client = client;
  }

  @Override
  public FormPoster.HttpResponse get(String url, Map<String, String> headers)
      throws IOException, InterruptedException {
    HttpRequest.Builder builder =
        HttpRequest.newBuilder()
            .uri(URI.create(url))
            .timeout(Duration.ofSeconds(60))
            .GET();
    if (headers != null) {
      headers.forEach(builder::header);
    }
    HttpResponse<String> response = client.send(builder.build(), HttpResponse.BodyHandlers.ofString());
    int status = response.statusCode();
    boolean ok = status >= 200 && status < 300;
    return new FormPoster.HttpResponse(status, ok, response.body() == null ? "" : response.body());
  }
}
