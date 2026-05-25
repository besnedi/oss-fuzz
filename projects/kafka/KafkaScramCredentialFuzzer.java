public class KafkaScramCredentialFuzzer {
  public static void fuzzerTestOneInput(byte[] input) {
    final String encoded = FuzzSupport.utf8(input, 8192);
    FuzzSupport.run(() -> {
      Object credential = FuzzSupport.callStatic(
          "org.apache.kafka.common.security.scram.internals.ScramCredentialUtils",
          "credentialFromString",
          new Class<?>[] {String.class},
          encoded);
      FuzzSupport.callStatic(
          "org.apache.kafka.common.security.scram.internals.ScramCredentialUtils",
          "credentialToString",
          new Class<?>[] {FuzzSupport.c("org.apache.kafka.common.security.scram.ScramCredential")},
          credential);
      FuzzSupport.touch(credential);
    });
  }
}
