package dev.rmkr.jwtoauthcli.cli;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;

final class CliJson {
  private static final ObjectMapper PRETTY =
      new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
  private static final ObjectMapper COMPACT = new ObjectMapper();

  private CliJson() {}

  static void writeJson(PrintStream out, Object value, boolean compact) throws Exception {
    ObjectMapper mapper = compact ? COMPACT : PRETTY;
    byte[] bytes = mapper.writeValueAsBytes(value);
    out.write(bytes);
    out.write('\n');
    out.flush();
  }

  static void writeJson(OutputStream out, Object value, boolean compact) throws Exception {
    writeJson(new PrintStream(out, false, StandardCharsets.UTF_8), value, compact);
  }
}
