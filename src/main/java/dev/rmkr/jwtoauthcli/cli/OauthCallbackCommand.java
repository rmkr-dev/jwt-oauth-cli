package dev.rmkr.jwtoauthcli.cli;

import dev.rmkr.jwtoauthcli.oauth.CallbackSupport;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.io.PrintStream;
import java.io.PrintWriter;
import java.time.Duration;
import java.util.concurrent.Callable;

import static dev.rmkr.jwtoauthcli.cli.CliJson.writeJson;

@Command(
    name = "callback",
    description =
        "Listen once on a loopback redirect URI and print the authorization code (or error) as JSON")
public class OauthCallbackCommand implements Callable<Integer> {

  @Option(
      names = "--redirect-uri",
      required = true,
      description = "Redirect URI to serve, e.g. http://127.0.0.1:8765/callback")
  String redirectUri;

  @Option(
      names = "--bind",
      description = "Listen address (default: the redirect URI host; localhost binds the loopback address)")
  String bind;

  @Option(
      names = "--timeout-seconds",
      defaultValue = "300",
      description = "Give up after this many seconds (default: 300)")
  long timeoutSeconds;

  @Option(
      names = "--expected-state",
      description = "Require the redirect state to equal this value")
  String expectedState;

  @Option(names = "--success-html", description = "HTML page shown in the browser on success")
  String successHtml;

  @Option(names = "--error-html", description = "HTML page shown in the browser on error")
  String errorHtml;

  @Option(
      names = {"-c", "--compact"},
      description = "Print compact single-line JSON")
  boolean compact;

  PrintStream out = System.out;
  PrintStream errStream = System.err;

  @Override
  public Integer call() {
    PrintWriter err = new PrintWriter(errStream, true);
    try {
      if (timeoutSeconds <= 0) {
        throw new IllegalArgumentException("--timeout-seconds must be greater than 0");
      }
      CallbackSupport.Endpoint endpoint = CallbackSupport.parseRedirectUri(redirectUri);
      CallbackSupport.Options options =
          new CallbackSupport.Options(redirectUri)
              .bind(bind)
              .timeout(Duration.ofSeconds(timeoutSeconds))
              .expectedState(expectedState)
              .successHtml(successHtml)
              .errorHtml(errorHtml)
              .onListening(
                  addr ->
                      err.println(
                          "Waiting for redirect on http://"
                              + endpoint.host()
                              + ":"
                              + addr.getPort()
                              + endpoint.path()
                              + " (timeout "
                              + timeoutSeconds
                              + "s)"));

      CallbackSupport.Result result = CallbackSupport.await(options);
      switch (result.outcome()) {
        case CODE:
          writeJson(out, result.fields(), compact);
          return 0;
        case ERROR:
        case STATE_MISMATCH:
          writeJson(out, result.fields(), compact);
          err.println(result.message());
          return 1;
        default:
          err.println(result.message());
          return 1;
      }
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      err.println("Interrupted while waiting for redirect");
      return 1;
    } catch (Exception e) {
      err.println(e.getMessage());
      return 1;
    }
  }
}
