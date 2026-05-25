import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInput;
import java.io.DataInputStream;
import java.io.DataOutput;
import java.io.DataOutputStream;

public class AccumuloMutationFuzzer {
  public static void fuzzerTestOneInput(byte[] input) {
    final byte[] data = FuzzSupport.cap(input, 65536);
    final String[] parts = FuzzSupport.strings(data, 5, 256);

    FuzzSupport.run(() -> {
      Class<?> textClass = FuzzSupport.c("org.apache.hadoop.io.Text");
      Object row = FuzzSupport.construct("org.apache.hadoop.io.Text", new Class<?>[] {String.class}, parts[0]);
      Object cf = FuzzSupport.construct("org.apache.hadoop.io.Text", new Class<?>[] {String.class}, parts[1]);
      Object cq = FuzzSupport.construct("org.apache.hadoop.io.Text", new Class<?>[] {String.class}, parts[2]);
      Object mutation = FuzzSupport.construct("org.apache.accumulo.core.data.Mutation", new Class<?>[] {textClass}, row);
      FuzzSupport.call(mutation, "put", new Class<?>[] {textClass, textClass, byte[].class}, cf, cq, data);
      FuzzSupport.call(mutation, "size", new Class<?>[] {});
      FuzzSupport.call(mutation, "numBytes", new Class<?>[] {});
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      FuzzSupport.call(mutation, "write", new Class<?>[] {DataOutput.class}, new DataOutputStream(out));
      FuzzSupport.touch(mutation);
    });

    FuzzSupport.run(() -> {
      Object mutation = FuzzSupport.construct("org.apache.accumulo.core.data.Mutation", new Class<?>[] {});
      FuzzSupport.call(mutation, "readFields", new Class<?>[] {DataInput.class},
          new DataInputStream(new ByteArrayInputStream(data)));
      FuzzSupport.touch(mutation);
    });
  }
}
