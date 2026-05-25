import java.lang.reflect.Method;

public class NifiFlowJsonFuzzer {
  private static final String[] TARGET_CLASSES = {
      "org.apache.nifi.web.api.entity.FlowEntity",
      "org.apache.nifi.web.api.entity.ProcessGroupEntity",
      "org.apache.nifi.web.api.entity.ProcessorEntity",
      "org.apache.nifi.web.api.entity.ConnectionEntity",
      "org.apache.nifi.web.api.entity.ControllerServiceEntity",
      "org.apache.nifi.web.api.entity.ParameterContextEntity",
      "org.apache.nifi.web.api.entity.ReportingTaskEntity",
      "org.apache.nifi.flow.VersionedProcessGroup",
      "org.apache.nifi.flow.VersionedFlowSnapshot",
      "org.apache.nifi.registry.flow.VersionedFlowSnapshot"
  };

  public static void fuzzerTestOneInput(byte[] input) {
    final byte[] data = FuzzSupport.cap(input, 1 << 20);
    for (String targetClassName : TARGET_CLASSES) {
      FuzzSupport.run(() -> {
        Class<?> objectMapperClass = FuzzSupport.c("com.fasterxml.jackson.databind.ObjectMapper");
        Object mapper = objectMapperClass.getDeclaredConstructor().newInstance();
        Class<?> targetClass = FuzzSupport.c(targetClassName);
        Method readValue = objectMapperClass.getMethod("readValue", byte[].class, Class.class);
        Object object = readValue.invoke(mapper, data, targetClass);
        FuzzSupport.touch(object);
        objectMapperClass.getMethod("writeValueAsBytes", Object.class).invoke(mapper, object);
      });
    }
  }
}
