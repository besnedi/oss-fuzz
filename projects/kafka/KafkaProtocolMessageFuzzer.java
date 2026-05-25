import java.nio.ByteBuffer;

public class KafkaProtocolMessageFuzzer {
  private static final String[] REQUEST_CLASSES = {
      "org.apache.kafka.common.requests.ApiVersionsRequest",
      "org.apache.kafka.common.requests.MetadataRequest",
      "org.apache.kafka.common.requests.ProduceRequest",
      "org.apache.kafka.common.requests.FetchRequest",
      "org.apache.kafka.common.requests.JoinGroupRequest",
      "org.apache.kafka.common.requests.SyncGroupRequest",
      "org.apache.kafka.common.requests.OffsetFetchRequest",
      "org.apache.kafka.common.requests.FindCoordinatorRequest"
  };

  public static void fuzzerTestOneInput(byte[] input) {
    final byte[] data = FuzzSupport.cap(input, 262144);
    for (String requestClass : REQUEST_CLASSES) {
      for (short version = 0; version < 8; version++) {
        final short parsedVersion = version;
        FuzzSupport.run(() -> {
          try {
            Class<?> readable = FuzzSupport.c("org.apache.kafka.common.protocol.Readable");
            Object accessor = FuzzSupport.construct(
                "org.apache.kafka.common.protocol.ByteBufferAccessor",
                new Class<?>[] {ByteBuffer.class},
                ByteBuffer.wrap(data));
            Object request = FuzzSupport.callStatic(requestClass, "parse",
                new Class<?>[] {readable, short.class}, accessor, parsedVersion);
            FuzzSupport.touch(request);
          } catch (NoSuchMethodException ignored) {
            Object request = FuzzSupport.callStatic(requestClass, "parse",
                new Class<?>[] {ByteBuffer.class, short.class}, ByteBuffer.wrap(data), parsedVersion);
            FuzzSupport.touch(request);
          }
        });
      }
    }
  }
}
