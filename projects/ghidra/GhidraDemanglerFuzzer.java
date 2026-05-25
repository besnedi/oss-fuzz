public class GhidraDemanglerFuzzer {
  private static final String[] DEMANGLERS = {
      "ghidra.app.util.demangler.gnu.GnuDemangler",
      "ghidra.app.util.demangler.microsoft.MicrosoftDemangler",
      "ghidra.app.util.demangler.swift.SwiftDemangler"
  };

  public static void fuzzerTestOneInput(byte[] input) {
    final String symbol = FuzzSupport.utf8(input, 8192);
    for (String demanglerClass : DEMANGLERS) {
      FuzzSupport.run(() -> {
        Object demangler = FuzzSupport.construct(demanglerClass, new Class<?>[] {});
        Object result = FuzzSupport.call(demangler, "demangle", new Class<?>[] {String.class}, symbol);
        FuzzSupport.touch(result);
      });
    }
  }
}
