#!/bin/bash -eu
# Build Accumulo jars and package a Jazzer fuzzer
set -o pipefail

ACC_DIR="$SRC/accumulo"

# Use a newer version of maven
MAVEN_VER=3.9.9
MAVEN_DIR=/tmp/apache-maven-$MAVEN_VER
if ! [ -x "$MAVEN_DIR/bin/mvn" ]; then
  curl -fsSL -o /tmp/maven.tgz https://archive.apache.org/dist/maven/maven-3/$MAVEN_VER/binaries/apache-maven-$MAVEN_VER-bin.tar.gz
  tar -C /tmp -xzf /tmp/maven.tgz
fi
MVN="$MAVEN_DIR/bin/mvn"
export MAVEN_OPTS="-Xmx1g"   # optional but helpful


# remove comments from maven.config file...
pushd "$ACC_DIR"
[ -f .mvn/maven.config ] && sed -i -e 's/\r$//' -e '/^[[:space:]]*#/d' -e '/^[[:space:]]*$/d' .mvn/maven.config || true
popd


# 1) Build Accumulo (skip tests for speed)
# Build core modules that contain the classes we fuzz
pushd "$ACC_DIR"
$MVN -q -DskipTests -pl :accumulo-core,:accumulo-start -am package
#mvn -q -DskipTests -pl :accumulo-core,:accumulo-fate,:accumulo-start -am package
popd

# 2) Assemble runtime classpath: copy all relevant jars into $OUT
find "$ACC_DIR" -type f -path '*/target/*.jar' \
  ! -path '*/target/test-classes/*' \
  ! -name '*-tests.jar' ! -name '*-test.jar' \
  -exec cp -v {} "$OUT/" \;

# 3) Pull compile-time deps for accumulo-core into /out/deps
pushd "$ACC_DIR"
$MVN -q -DskipTests -pl :accumulo-core -am \
  dependency:copy-dependencies \
  -DincludeScope=compile \
  -DoutputDirectory=$OUT/deps
popd

# 4) Create a colon-separated classpath of jars in $OUT
#PROJECT_CP="$(find "$OUT" -maxdepth 1 -name '*.jar' -printf '%p:' | sed 's/:$//')"
ACC_JARS="$(find "$OUT" -maxdepth 1 -type f -name '*.jar' -printf '%p:' | sed 's/:$//')"
DEP_JARS="$(find "$OUT/deps" -type f -name '*.jar' -printf '%p:' | sed 's/:$//')"

BUILD_CP="${ACC_JARS}:${DEP_JARS}" #:${JAZZER_API_PATH}"

# 5) Compile fuzzer(s) with the proper classpath
mkdir -p /workspace/fuzzbin
javac --release 17 -cp "$BUILD_CP" -d /workspace/fuzzbin "$SRC/ColumnVisibilityFuzzer.java"

# Package into a single jar
jar cf "$OUT/accumulo-fuzzers.jar" -C /workspace/fuzzbin .

# 6) Emit Jazzer launcher(s)

JAZZER_BIN="${JAZZER_DRIVER:-$OUT/jazzer_driver}"
JAZZER_API="${JAZZER_API_PATH:-/usr/local/lib/jazzer_api_deploy.jar}"
JAZZER_AGENT_PATH="${JAZZER_AGENT_PATH:-$OUT/jazzer_agent_deploy.jar}"
RUNTIME_CP="${OUT}:${OUT}/accumulo-fuzzers.jar:${JAZZER_API}:${ACC_JARS}:${DEP_JARS}"
cat > "$OUT/ColumnVisibilityFuzzer" <<EOF
#!/bin/bash
set -euo pipefail
exec "$JAZZER_BIN" \
  --agent_path="$JAZZER_AGENT_PATH" \
  --cp="$RUNTIME_CP" \
  --target_class=ColumnVisibilityFuzzer "\$@"
EOF
chmod 755 "$OUT/ColumnVisibilityFuzzer"
ls -altr "$OUT"
