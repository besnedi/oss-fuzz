import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.format.macho.MachHeader;
import ghidra.util.task.TaskMonitor;

import java.lang.reflect.Method;

public class MachHeaderFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    byte[] bytes = data.consumeBytes(data.remainingBytes());
    if (bytes.length == 0) return;

    try {
      BinaryReader br = new BinaryReader(new ByteArrayProvider(bytes), /*little*/ true);

      MachHeader mh = null;
      // Try (BinaryReader, TaskMonitor) then (BinaryReader)
      mh = (MachHeader) tryStatic("ghidra.app.util.bin.format.macho.MachHeader",
                                  "createMachHeader",
                                  new Class<?>[]{BinaryReader.class, TaskMonitor.class},
                                  new Object[]{br, TaskMonitor.DUMMY});
      if (mh == null) {
        mh = (MachHeader) tryStatic("ghidra.app.util.bin.format.macho.MachHeader",
                                    "createMachHeader",
                                    new Class<?>[]{BinaryReader.class},
                                    new Object[]{br});
      }
      if (mh == null) return;

      // Probe likely getters (ignore if absent)
      invokeNoThrow(mh, "getCpuType");
      invokeNoThrow(mh, "getCpuSubType");
      invokeNoThrow(mh, "getFileType");
      invokeNoThrow(mh, "getFlags");
      invokeNoThrow(mh, "getLoadCommands");
    } catch (OutOfMemoryError | StackOverflowError oom) {
      throw oom;
    } catch (Throwable ignored) {
      // parse failures are expected
    }
  }

  private static Object tryStatic(String cls, String name, Class<?>[] sig, Object[] args) {
    try {
      Class<?> c = Class.forName(cls);
      Method m = c.getMethod(name, sig);
      return m.invoke(null, args);
    } catch (Throwable ignored) { return null; }
  }

  private static void invokeNoThrow(Object target, String method) {
    try {
      Method m = target.getClass().getMethod(method);
      m.invoke(target);
    } catch (Throwable ignored) {}
  }
}

