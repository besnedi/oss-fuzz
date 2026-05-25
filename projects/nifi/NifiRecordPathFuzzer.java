public class NifiRecordPathFuzzer {
  public static void fuzzerTestOneInput(byte[] input) {
    final String path = FuzzSupport.utf8(input, 4096);
    FuzzSupport.run(() -> {
      Object recordPath = FuzzSupport.callStatic(
          "org.apache.nifi.record.path.RecordPath",
          "compile",
          new Class<?>[] {String.class},
          path);
      FuzzSupport.touch(recordPath);
      FuzzSupport.call(recordPath, "getPath", new Class<?>[] {});
      FuzzSupport.call(recordPath, "isAbsolute", new Class<?>[] {});
    });
  }
}
