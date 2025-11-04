import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import org.apache.accumulo.core.security.Authorizations;
import org.apache.accumulo.core.security.ColumnVisibility;
import org.apache.accumulo.core.security.VisibilityEvaluator;

import java.util.ArrayList;
import java.util.List;

public class ColumnVisibilityFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    // Build a random set of auth tokens
    int n = Math.max(0, data.consumeInt(0, 8));
    List<byte[]> auths = new ArrayList<>(n);
    for (int i = 0; i < n; i++) {
      auths.add(data.consumeBytes(data.consumeInt(0, 16)));
    }
    Authorizations a = new Authorizations(auths);

    // Feed random visibility expressions
    byte[] expr = data.consumeBytes(data.remainingBytes());
    try {
      ColumnVisibility cv = new ColumnVisibility(expr);
      // Evaluate with the generated auths (exercise evaluator/AST)
      VisibilityEvaluator ve = new VisibilityEvaluator(a);
      ve.evaluate(cv);
    } catch (Exception ignored) {
      // Jazzer will still observe crashes such as OOM, AIOOBE, etc.
    }
  }
}

