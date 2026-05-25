import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInput;
import java.io.DataInputStream;
import java.io.DataOutput;
import java.io.DataOutputStream;

public class AccumuloKeyValueFuzzer {
  public static void fuzzerTestOneInput(byte[] input) {
    final byte[] data = FuzzSupport.cap(input, 65536);

    FuzzSupport.run(() -> {
      Object key = FuzzSupport.construct("org.apache.accumulo.core.data.Key", new Class<?>[] {});
      FuzzSupport.call(key, "readFields", new Class<?>[] {DataInput.class},
          new DataInputStream(new ByteArrayInputStream(data)));
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      FuzzSupport.call(key, "write", new Class<?>[] {DataOutput.class}, new DataOutputStream(out));
      FuzzSupport.touch(key);
    });

    FuzzSupport.run(() -> {
      Object value = FuzzSupport.construct("org.apache.accumulo.core.data.Value", new Class<?>[] {byte[].class},
          (Object) data);
      FuzzSupport.call(value, "getSize", new Class<?>[] {});
      FuzzSupport.call(value, "get", new Class<?>[] {});
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      FuzzSupport.call(value, "write", new Class<?>[] {DataOutput.class}, new DataOutputStream(out));
      FuzzSupport.touch(value);
    });
  }
}
