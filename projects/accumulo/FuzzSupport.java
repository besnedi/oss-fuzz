import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

final class FuzzSupport {
  private FuzzSupport() {}

  @FunctionalInterface
  interface ThrowingRunnable {
    void run() throws Throwable;
  }

  static void run(ThrowingRunnable runnable) {
    try {
      runnable.run();
    } catch (Throwable t) {
      handle(t);
    }
  }

  static void handle(Throwable t) {
    Throwable u = unwrap(t);
    if (u instanceof VirtualMachineError) {
      throw (VirtualMachineError) u;
    }
    if (u instanceof LinkageError || u instanceof ClassNotFoundException ||
        u instanceof NoSuchMethodException || u instanceof NoSuchFieldException) {
      return;
    }
    if (u instanceof Error) {
      sneakyThrow(u);
    }
    if (u instanceof NullPointerException || u instanceof ArrayIndexOutOfBoundsException ||
        u instanceof IndexOutOfBoundsException || u instanceof NegativeArraySizeException ||
        u instanceof ClassCastException) {
      sneakyThrow(u);
    }
    // Most remaining exceptions are parser/domain rejections for malformed fuzz input.
  }

  static Throwable unwrap(Throwable t) {
    Throwable current = t;
    while (current instanceof InvocationTargetException &&
        ((InvocationTargetException) current).getTargetException() != null) {
      current = ((InvocationTargetException) current).getTargetException();
    }
    return current;
  }

  @SuppressWarnings("unchecked")
  static <E extends Throwable> void sneakyThrow(Throwable t) throws E {
    throw (E) t;
  }

  static byte[] cap(byte[] input, int maxLen) {
    if (input.length <= maxLen) {
      return input;
    }
    return Arrays.copyOf(input, maxLen);
  }

  static byte[] slice(byte[] input, int offset, int maxLen) {
    if (offset >= input.length) {
      return new byte[0];
    }
    int len = Math.min(maxLen, input.length - offset);
    return Arrays.copyOfRange(input, offset, offset + len);
  }

  static String utf8(byte[] input, int maxLen) {
    return new String(cap(input, maxLen), StandardCharsets.UTF_8);
  }

  static String[] strings(byte[] input, int count, int maxEach) {
    String[] out = new String[count];
    int index = 0;
    for (int i = 0; i < count; i++) {
      int limit = Math.min(input.length, index + maxEach);
      int end = index;
      while (end < limit && input[end] != 0) {
        end++;
      }
      out[i] = new String(input, index, Math.max(0, end - index), StandardCharsets.UTF_8);
      index = Math.min(input.length, end + 1);
    }
    return out;
  }

  static Class<?> c(String className) throws ClassNotFoundException {
    return Class.forName(className);
  }

  static Object construct(String className, Class<?>[] parameterTypes, Object... args) throws Exception {
    Constructor<?> constructor = c(className).getDeclaredConstructor(parameterTypes);
    constructor.setAccessible(true);
    return constructor.newInstance(args);
  }

  static Method findMethod(Class<?> targetClass, String methodName, Class<?>[] parameterTypes)
      throws NoSuchMethodException {
    try {
      return targetClass.getMethod(methodName, parameterTypes);
    } catch (NoSuchMethodException ignored) {
      Class<?> current = targetClass;
      while (current != null) {
        try {
          return current.getDeclaredMethod(methodName, parameterTypes);
        } catch (NoSuchMethodException next) {
          current = current.getSuperclass();
        }
      }
      throw ignored;
    }
  }

  static Object call(Object target, String methodName, Class<?>[] parameterTypes, Object... args) throws Exception {
    Method method = findMethod(target.getClass(), methodName, parameterTypes);
    method.setAccessible(true);
    return method.invoke(target, args);
  }

  static Object callStatic(String className, String methodName, Class<?>[] parameterTypes, Object... args) throws Exception {
    Method method = findMethod(c(className), methodName, parameterTypes);
    method.setAccessible(true);
    return method.invoke(null, args);
  }

  @SuppressWarnings({"unchecked", "rawtypes"})
  static Object enumConstant(String className, String name) throws Exception {
    return Enum.valueOf((Class<Enum>) c(className), name);
  }

  static void touch(Object object) {
    if (object != null) {
      object.hashCode();
      object.toString();
    }
  }
}
