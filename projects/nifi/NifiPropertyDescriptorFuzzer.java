public class NifiPropertyDescriptorFuzzer {
  public static void fuzzerTestOneInput(byte[] input) {
    final String[] parts = FuzzSupport.strings(input, 6, 256);
    FuzzSupport.run(() -> {
      Object builder = FuzzSupport.construct(
          "org.apache.nifi.components.PropertyDescriptor$Builder",
          new Class<?>[] {});
      FuzzSupport.call(builder, "name", new Class<?>[] {String.class}, parts[0]);
      FuzzSupport.call(builder, "displayName", new Class<?>[] {String.class}, parts[1]);
      FuzzSupport.call(builder, "description", new Class<?>[] {String.class}, parts[2]);
      FuzzSupport.call(builder, "defaultValue", new Class<?>[] {String.class}, parts[3]);
      FuzzSupport.call(builder, "required", new Class<?>[] {boolean.class}, (input.length & 1) == 0);
      FuzzSupport.call(builder, "sensitive", new Class<?>[] {boolean.class}, (input.length & 2) == 0);
      Object descriptor = FuzzSupport.call(builder, "build", new Class<?>[] {});
      FuzzSupport.touch(descriptor);
    });
  }
}
