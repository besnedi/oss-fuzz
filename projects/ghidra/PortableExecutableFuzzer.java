import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.format.pe.PortableExecutable;
import ghidra.util.task.TaskMonitor;

import java.lang.reflect.Method;

public class PortableExecutableFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    byte[] bytes = data.consumeBytes(data.remainingBytes());
    if (bytes.length == 0) return;

    try {
      BinaryReader br = new BinaryReader(new ByteArrayProvider(bytes), /*little*/ true);

      PortableExecutable pe = null;
      // Try common factories:
      // 1) (BinaryReader, boolean)   // parseSectionContents
      pe = (PortableExecutable) tryStatic("ghidra.app.util.bin.format.pe.PortableExecutable",
                                          "createPortableExecutable",
                                          new Class<?>[]{BinaryReader.class, boolean.class},
                                          new Object[]{br, false});
      // 2) (BinaryReader)
      if (pe == null) {
        pe = (PortableExecutable) tryStatic("ghidra.app.util.bin.format.pe.PortableExecutable",
                                            "createPortableExecutable",
                                            new Class<?>[]{BinaryReader.class},
                                            new Object[]{br});
      }
      // 3) (BinaryReader, boolean, TaskMonitor)
      if (pe == null) {
        pe = (PortableExecutable) tryStatic("ghidra.app.util.bin.format.pe.PortableExecutable",
                                            "createPortableExecutable",
                                            new Class<?>[]{BinaryReader.class, boolean.class, TaskMonitor.class},
                                            new Object[]{br, false, TaskMonitor.DUMMY});
      }
      if (pe == null) return;

      // Nudge common paths:
      invokeNoThrow(pe, "getNTHeader");
      invokeNoThrow(pe, "getSectionHeaders");
      Object nt = tryInvoke(pe, "getNTHeader");
      if (nt != null) {
        tryInvoke(nt, "getOptionalHeader");
        tryInvoke(nt, "getFileHeader");
      }
    } catch (OutOfMemoryError | StackOverflowError oom) {
      throw oom;
    } catch (Throwable ignored) {
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

  private static Object tryInvoke(Object target, String method) {
    try {
      Method m = target.getClass().getMethod(method);
      return m.invoke(target);
    } catch (Throwable ignored) { return null; }
  }
}

