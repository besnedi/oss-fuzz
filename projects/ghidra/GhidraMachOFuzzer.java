public class GhidraMachOFuzzer {
  public static void fuzzerTestOneInput(byte[] input) {
    final byte[] data = FuzzSupport.cap(input, 1 << 20);
    FuzzSupport.run(() -> {
      Object provider = FuzzSupport.construct("ghidra.app.util.bin.ByteArrayProvider",
          new Class<?>[] {byte[].class}, (Object) data);
      Object header = FuzzSupport.construct("ghidra.app.util.bin.format.macho.MachHeader",
          new Class<?>[] {FuzzSupport.c("ghidra.app.util.bin.ByteProvider")}, provider);
      FuzzSupport.call(header, "parse", new Class<?>[] {});
      FuzzSupport.touch(header);
    });
  }
}
