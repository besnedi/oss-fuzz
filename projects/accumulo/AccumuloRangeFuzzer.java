import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInput;
import java.io.DataInputStream;
import java.io.DataOutput;
import java.io.DataOutputStream;

public class AccumuloRangeFuzzer {
  public static void fuzzerTestOneInput(byte[] input) {
    final byte[] data = FuzzSupport.cap(input, 65536);
    final String row = FuzzSupport.utf8(data, 4096);

    FuzzSupport.run(() -> {
      Object range = FuzzSupport.construct("org.apache.accumulo.core.data.Range", new Class<?>[] {String.class}, row);
      Object key = FuzzSupport.construct("org.apache.accumulo.core.data.Key", new Class<?>[] {});
      FuzzSupport.call(range, "contains", new Class<?>[] {FuzzSupport.c("org.apache.accumulo.core.data.Key")}, key);
      FuzzSupport.touch(range);
    });

    FuzzSupport.run(() -> {
      Object range = FuzzSupport.construct("org.apache.accumulo.core.data.Range", new Class<?>[] {});
      FuzzSupport.call(range, "readFields", new Class<?>[] {DataInput.class},
          new DataInputStream(new ByteArrayInputStream(data)));
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      FuzzSupport.call(range, "write", new Class<?>[] {DataOutput.class}, new DataOutputStream(out));
      FuzzSupport.touch(range);
    });
  }
}
