#!/bin/bash
set -euo pipefail

PROJECT_NAME=nifi
export MAVEN_OPTS="-Dmaven.repo.local=$WORK/m2 -Xmx2600m -Djava.awt.headless=true"
chmod +x ./mvnw
./mvnw -B -ntp -T1C \
  -DskipTests -Dmaven.test.skip=true -DskipITs \
  -Dcheckstyle.skip=true -Drat.skip=true -Denforcer.skip=true \
  -Dspotbugs.skip=true -Dspotless.check.skip=true -Dspotless.apply.skip=true \
  install

mkdir -p "$OUT/jars" "$WORK/fuzzer-classes"
copy_jars() {
  local source_dir="$1"
  local dest_dir="$2"
  [ -d "$source_dir" ] || return 0
  find "$source_dir" -type f -name '*.jar' \
    ! -name '*-sources.jar' ! -name '*-javadoc.jar' ! -name '*-tests.jar' ! -name '*-test.jar' ! -name 'original-*.jar' \
    -print0 | sort -z | while IFS= read -r -d '' jar; do
      local sha base
      sha=$(sha1sum "$jar" | awk '{print substr($1,1,12)}')
      base=$(basename "$jar")
      cp "$jar" "$dest_dir/${sha}_${base}"
    done
}
copy_jars "$PWD" "$OUT/jars"
copy_jars "$WORK/m2" "$OUT/jars"

javac -cp "$JAZZER_API_PATH" -d "$WORK/fuzzer-classes" "$SRC"/*.java
jar cf "$OUT/fuzzers.jar" -C "$WORK/fuzzer-classes" .
cp "$SRC"/*.dict "$SRC"/*.options "$SRC"/*_seed_corpus.zip "$OUT/" 2>/dev/null || true

for fuzzer_java in "$SRC"/*Fuzzer.java; do
  fuzzer_basename=$(basename "$fuzzer_java" .java)
  cat > "$OUT/$fuzzer_basename" <<EOF2
#!/bin/bash
# LLVMFuzzerTestOneInput
set -euo pipefail
this_dir=\$(cd "\$(dirname "\$0")" && pwd)
runtime_cp="\$this_dir/fuzzers.jar:\$this_dir"
shopt -s nullglob
for jar in "\$this_dir"/jars/*.jar; do runtime_cp="\$runtime_cp:\$jar"; done
tmp_dir="\${TMPDIR:-/tmp}/oss-fuzz-$PROJECT_NAME-$fuzzer_basename"
mkdir -p "\$tmp_dir"
LD_LIBRARY_PATH="\$JVM_LD_LIBRARY_PATH:\$this_dir:\$this_dir/lib:\${LD_LIBRARY_PATH:-}" \
  "\$this_dir/jazzer_driver" \
  --agent_path="\$this_dir/jazzer_agent_deploy.jar" \
  --cp="\$runtime_cp" \
  --target_class="$fuzzer_basename" \
  --jvm_args="-Xmx2600m:-Xss1m:-Djava.awt.headless=true:-Dfile.encoding=UTF-8:-Duser.home=\$tmp_dir:-Djava.io.tmpdir=\$tmp_dir" \
  --instrumentation_excludes="java.**,javax.**,sun.**,com.sun.**,jdk.**,org.junit.**,org.mockito.**,org.slf4j.**,ch.qos.logback.**" \
  "\$@"
EOF2
  chmod +x "$OUT/$fuzzer_basename"
done
