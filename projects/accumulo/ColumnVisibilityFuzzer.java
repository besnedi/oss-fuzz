import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import org.apache.accumulo.core.security.Authorizations;
import org.apache.accumulo.core.security.ColumnVisibility;
import org.apache.accumulo.core.security.VisibilityEvaluator;
import org.apache.accumulo.core.security.VisibilityParseException;

import java.util.ArrayList;
import java.util.List;

public class ColumnVisibilityFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    // Build a non-empty, sane authorization set (1..6 tokens, 1..32 bytes each)
    int n = data.consumeInt(1, 6);
    List<byte[]> auths = new ArrayList<>(n);
    for (int i = 0; i < n; i++) {
      int len = data.consumeInt(1, 32);
      byte[] tok = data.consumeBytes(len);
      if (tok.length == 0) tok = new byte[]{'a'};
      auths.add(tok);
    }

    // Visibility expression (cap length for speed)
    String expr = data.consumeAsciiString(1024);

    try {
      ColumnVisibility cv = new ColumnVisibility(expr);
      Authorizations az = new Authorizations(auths);
      VisibilityEvaluator ve = new VisibilityEvaluator(az);

      // Evaluate the parsed expression (this API expects ColumnVisibility)
      ve.evaluate(cv);

    } catch (IllegalArgumentException | VisibilityParseException expected) {
      // Input validation / parse failures are normal; keep fuzzing.
      return;
    }
  }
}

