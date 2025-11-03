#!/bin/bash -eu
# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################
set -o pipefail

# ===== Choose Java level for the fuzzers =====
# Ghidra 10.3.x -> 17; Ghidra 11.x -> 21
JRE_RELEASE="${JRE_RELEASE:-17}"

# ===== Build Ghidra with a modern Gradle (no apt gradle) =====
GRADLE_VER="${GRADLE_VER:-7.6.4}"  # 7.3+ OK for JDK 17; 7.6.4 is a safe pick
curl -fsSL -o /tmp/gradle.zip "https://services.gradle.org/distributions/gradle-${GRADLE_VER}-bin.zip"
unzip -q /tmp/gradle.zip -d /tmp

cd "$SRC/ghidra"
/tmp/gradle-${GRADLE_VER}/bin/gradle --no-daemon -I gradle/support/fetchDependencies.gradle init
/tmp/gradle-${GRADLE_VER}/bin/gradle --no-daemon buildGhidra -x test

# ===== Collect runtime jars =====
unzip -q build/dist/ghidra_*.zip -d /src/ghidra-dist
export GHIDRA_SRC_HOME="$SRC/ghidra"
export GHIDRA_HOME=/src/ghidra-dist/ghidra_*

# Copy Ghidra jars (exclude test jars) into $OUT
find "$GHIDRA_SRC_HOME" -type f -path '*/build/libs/*.jar' ! -name '*-test.jar' ! -name '*-tests.jar' -exec cp -v {} "$OUT/" \;
find "$GHIDRA_HOME"    -type f -name '*.jar'               ! -name '*-test.jar' ! -name '*-tests.jar' -exec cp -v {} "$OUT/" \;

# Build a colon-separated classpath of ALL jars now in $OUT
PROJECT_CP="$(find "$OUT" -maxdepth 1 -type f -name '*.jar' -printf '%p:' | sed 's/:$//')"

# ===== Compile fuzzers and package into one jar =====
mkdir -p /workspace/fuzzbin
for fuzzer in $(find "$SRC" -maxdepth 1 -name '*Fuzzer.java'); do
  echo "Compiling $(basename "$fuzzer") with --release ${JRE_RELEASE}"
  javac --release "${JRE_RELEASE}" \
        -cp "${PROJECT_CP}:${JAZZER_API_PATH}" \
        -d /workspace/fuzzbin \
        "$fuzzer"
done

jar cf "$OUT/ghidra-fuzzers.jar" -C /workspace/fuzzbin .

# ===== Emit Jazzer launchers (one per fuzzer class) =====
RUNTIME_CP="$OUT:$JAZZER_API_PATH:$PROJECT_CP"

# Extract class names from the fuzzer jar (handles packages too)
for fqn in $(jar tf "$OUT/ghidra-fuzzers.jar" | grep 'Fuzzer.class$' | sed 's#.class$##; s#/#.#g'); do
  short_name="${fqn##*.}"
  cat > "$OUT/$short_name" <<EOF
#!/bin/bash
set -euo pipefail
this_dir="\$(dirname "\$0")"
# If you compiled with Java 21 (Ghidra 11.x), bundle a JRE 21 in /out/jre21 and uncomment:
# export JAVA_HOME="\$this_dir/jre21"
# export PATH="\$JAVA_HOME/bin:\$PATH"
exec "\$JAZZER_DRIVER" \
  --cp="$RUNTIME_CP" \
  --target_class="$fqn" \
  "\$@"
EOF
  chmod +x "$OUT/$short_name"
done
