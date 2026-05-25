public class GhidraDexFuzzer {
  public static void fuzzerTestOneInput(byte[] input) {
    final byte[] data = FuzzSupport.cap(input, 1 << 20);
    FuzzSupport.run(() -> {
      Object provider = FuzzSupport.construct("ghidra.app.util.bin.ByteArrayProvider",
          new Class<?>[] {byte[].class}, (Object) data);
      Object reader = FuzzSupport.construct("ghidra.app.util.bin.BinaryReader",
          new Class<?>[] {FuzzSupport.c("ghidra.app.util.bin.ByteProvider"), boolean.class}, provider, true);
      Object header = FuzzSupport.construct("ghidra.file.formats.android.dex.format.DexHeader",
          new Class<?>[] {FuzzSupport.c("ghidra.app.util.bin.BinaryReader")}, reader);
      FuzzSupport.call(header, "parse", new Class<?>[] {FuzzSupport.c("ghidra.app.util.bin.BinaryReader")}, reader);
      FuzzSupport.touch(header);
    });
  }
}
