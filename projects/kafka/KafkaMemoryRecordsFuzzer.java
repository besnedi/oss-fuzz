import java.nio.ByteBuffer;

public class KafkaMemoryRecordsFuzzer {
  public static void fuzzerTestOneInput(byte[] input) {
    final byte[] data = FuzzSupport.cap(input, 262144);
    FuzzSupport.run(() -> {
      Object records = FuzzSupport.callStatic(
          "org.apache.kafka.common.record.MemoryRecords",
          "readableRecords",
          new Class<?>[] {ByteBuffer.class},
          ByteBuffer.wrap(data));
      FuzzSupport.call(records, "validBytes", new Class<?>[] {});
      FuzzSupport.call(records, "firstBatchSize", new Class<?>[] {});
      Object batches = FuzzSupport.call(records, "batches", new Class<?>[] {});
      if (batches instanceof Iterable<?>) {
        int count = 0;
        for (Object batch : (Iterable<?>) batches) {
          FuzzSupport.touch(batch);
          FuzzSupport.call(batch, "magic", new Class<?>[] {});
          FuzzSupport.call(batch, "baseOffset", new Class<?>[] {});
          FuzzSupport.call(batch, "lastOffset", new Class<?>[] {});
          FuzzSupport.call(batch, "sizeInBytes", new Class<?>[] {});
          if (++count >= 16) {
            break;
          }
        }
      }
    });
  }
}
