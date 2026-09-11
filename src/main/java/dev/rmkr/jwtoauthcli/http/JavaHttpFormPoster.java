package dev.rmkr.jwtoauthcli.http;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.time.Duration;
import java.util.Map;

/** Default {@link FormPoster} backed by {@link java.net.http.HttpClient}. */
public final class JavaHttpFormPoster implements FormPoster {

  private final HttpClient client;

  public JavaHttpFormPoster() {
    this(
        HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(30))
            .followRedirects(HttpClient.Redirect.NEVER)
            .build());
  }

  public JavaHttpFormPoster(HttpClient client) {
    this.client = client;
  }

  @Override
  public FormPoster.HttpResponse post(String url, String formBody, Map<String, String> headers)
      throws IOException, InterruptedException {
    HttpRequest.Builder builder =
        HttpRequest.newBuilder()
            .uri(URI.create(url))
            .timeout(Duration.ofSeconds(60))
            .POST(HttpRequest.BodyPublishers.ofString(formBody));
    if (headers != null) {
      headers.forEach(builder::header);
    }
    java.net.http.HttpResponse<String> response =
        client.send(builder.build(), java.net.http.HttpResponse.BodyHandlers.ofString());
    int status = response.statusCode();
    boolean ok = status >= 200 && status < 300;
    return new FormPoster.HttpResponse(status, ok, response.body() == null ? "" : response.body());
  }
}
