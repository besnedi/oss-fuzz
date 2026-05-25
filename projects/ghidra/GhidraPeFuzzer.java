public class GhidraPeFuzzer {
  public static void fuzzerTestOneInput(byte[] input) {
    final byte[] data = FuzzSupport.cap(input, 1 << 20);
    FuzzSupport.run(() -> {
      Object provider = FuzzSupport.construct("ghidra.app.util.bin.ByteArrayProvider",
          new Class<?>[] {byte[].class}, (Object) data);
      Object layout = FuzzSupport.enumConstant(
          "ghidra.app.util.bin.format.pe.PortableExecutable$SectionLayout", "FILE");
      Object pe = FuzzSupport.construct("ghidra.app.util.bin.format.pe.PortableExecutable",
          new Class<?>[] {FuzzSupport.c("ghidra.app.util.bin.ByteProvider"), layout.getClass(), boolean.class, boolean.class},
          provider, layout, true, true);
      FuzzSupport.touch(pe);
    });
  }
}
