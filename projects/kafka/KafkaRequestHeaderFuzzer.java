import java.nio.ByteBuffer;

public class KafkaRequestHeaderFuzzer {
  public static void fuzzerTestOneInput(byte[] input) {
    final byte[] data = FuzzSupport.cap(input, 65536);
    FuzzSupport.run(() -> {
      Object header = FuzzSupport.callStatic(
          "org.apache.kafka.common.requests.RequestHeader",
          "parse",
          new Class<?>[] {ByteBuffer.class},
          ByteBuffer.wrap(data));
      FuzzSupport.touch(header);
      FuzzSupport.call(header, "apiKey", new Class<?>[] {});
      FuzzSupport.call(header, "apiVersion", new Class<?>[] {});
      FuzzSupport.call(header, "clientId", new Class<?>[] {});
    });
  }
}
