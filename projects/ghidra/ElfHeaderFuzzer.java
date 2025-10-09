import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.util.task.TaskMonitor;

import java.io.ByteArrayInputStream;
import java.lang.reflect.Method;

public class ElfHeaderFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    byte[] bytes = data.consumeBytes(data.remainingBytes());
    if (bytes.length == 0) return;

    try {
      BinaryReader br = new BinaryReader(new ByteArrayProvider(bytes), /*isLittleEndian*/ true);

      // Try createElfHeader(BinaryReader, TaskMonitor) first, else createElfHeader(BinaryReader)
      ElfHeader header = null;
      try {
        Method m = ElfHeader.class.getMethod("createElfHeader", BinaryReader.class, TaskMonitor.class);
        header = (ElfHeader) m.invoke(null, br, TaskMonitor.DUMMY);
      } catch (NoSuchMethodException nsme) {
        Method m = ElfHeader.class.getMethod("createElfHeader", BinaryReader.class);
        header = (ElfHeader) m.invoke(null, br);
      }

      if (header == null) return;

      // Touch a few fields safely (methods differ by version, so use reflection & ignore if missing)
      invokeNoThrow(header, "getMachine");
      invokeNoThrow(header, "getType");
      invokeNoThrow(header, "getProgramHeaders");
      invokeNoThrow(header, "getSectionHeaders");
      invokeNoThrow(header, "getEIdentClass"); // some versions
      invokeNoThrow(header, "getEIdentData");  // some versions

    } catch (OutOfMemoryError | StackOverflowError oom) {
      throw oom; // let Jazzer report resource errors
    } catch (Throwable ignore) {
      // parse failures and missing methods are expected for random input
    }
  }

  private static void invokeNoThrow(Object target, String method) {
    try {
      Method m = target.getClass().getMethod(method);
      m.invoke(target);
    } catch (Throwable ignored) { }
  }
}

