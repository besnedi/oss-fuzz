public class NifiExpressionLanguageFuzzer {
  public static void fuzzerTestOneInput(byte[] input) {
    final String expression = FuzzSupport.utf8(input, 4096);

    FuzzSupport.run(() -> {
      Class<?> parameterLookup = FuzzSupport.c("org.apache.nifi.parameter.ParameterLookup");
      Object compiler = FuzzSupport.construct(
          "org.apache.nifi.attribute.expression.language.StandardExpressionLanguageCompiler",
          new Class<?>[] {parameterLookup},
          (Object) null);
      FuzzSupport.call(compiler, "isValidExpression", new Class<?>[] {String.class}, expression);
      FuzzSupport.call(compiler, "validateExpression", new Class<?>[] {String.class, boolean.class}, expression, true);
      FuzzSupport.call(compiler, "getResultType", new Class<?>[] {String.class}, expression);
      Object query = FuzzSupport.call(compiler, "compile", new Class<?>[] {String.class}, expression);
      FuzzSupport.touch(query);
    });

    FuzzSupport.run(() -> {
      Object query = FuzzSupport.callStatic(
          "org.apache.nifi.attribute.expression.language.Query",
          "compile",
          new Class<?>[] {String.class},
          expression);
      FuzzSupport.touch(query);
    });
  }
}
