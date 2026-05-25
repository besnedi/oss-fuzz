public class AccumuloVisibilityFuzzer {
  public static void fuzzerTestOneInput(byte[] input) {
    final byte[] data = FuzzSupport.cap(input, 8192);
    final String[] auths = FuzzSupport.strings(data, 8, 128);

    FuzzSupport.run(() -> {
      Object visibility = FuzzSupport.construct(
          "org.apache.accumulo.core.security.ColumnVisibility",
          new Class<?>[] {byte[].class},
          (Object) data);
      FuzzSupport.touch(visibility);
      FuzzSupport.call(visibility, "flatten", new Class<?>[] {});
    });

    FuzzSupport.run(() -> {
      Object visibility = FuzzSupport.construct(
          "org.apache.accumulo.core.security.ColumnVisibility",
          new Class<?>[] {byte[].class},
          (Object) data);
      Object authorizations = FuzzSupport.construct(
          "org.apache.accumulo.core.security.Authorizations",
          new Class<?>[] {String[].class},
          (Object) auths);
      Object evaluator = FuzzSupport.construct(
          "org.apache.accumulo.core.security.VisibilityEvaluator",
          new Class<?>[] {FuzzSupport.c("org.apache.accumulo.core.security.Authorizations")},
          authorizations);
      FuzzSupport.call(evaluator, "evaluate",
          new Class<?>[] {FuzzSupport.c("org.apache.accumulo.core.security.ColumnVisibility")},
          visibility);
    });
  }
}
