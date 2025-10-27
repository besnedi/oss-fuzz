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

# build project - per ghidra README.md, using ./gradlew instead of gradle
# --no-daemon disables gradle background process
# -x exclude any tests
export GHIDRA_SRC_HOME=/src/ghidra/
cd $GHIDRA_SRC_HOME
./gradlew --no-daemon -I gradle/support/fetchDependencies.gradle
./gradlew --no-daemon buildGhidra -x test

# get the jars (https://google.github.io/oss-fuzz/getting-started/new-project-guide/jvm-lang/)
unzip build/dist/ghidra_*.zip -d ${SRC}/ghidra-dist
export GHIDRA_HOME=/src/ghidra-dist/ghidra_*/

find ${GHIDRA_SRC_HOME}/ -name "*.jar" -type f ! -name "*-test.jar" ! -name "*-tests.jar" -exec cp -v {} "${OUT}/" \;
find ${GHIDRA_HOME}/ -name "*.jar" -type f ! -name "*-test.jar" ! -name "*-tests.jar" -exec cp -v {} "${OUT}/" \;
PROJECT_JARS=$(find ${OUT}/ -name "*.jar" -type f)

# Step 2: build the fuzzers

# The classpath at build-time includes the project jars in $OUT as well as the
# Jazzer API.
BUILD_CLASSPATH=$(echo ${PROJECT_JARS} | tr ' ' ':'):${JAZZER_API_PATH}

# All .jar and .class files lie in the same directory as the fuzzer at runtime.
RUNTIME_CLASSPATH=$(echo ${PROJECT_JARS} | tr ' ' ':')
#| xargs printf -- "\$this_dir/%s:"):\$this_dir

for fuzzer in $(find $SRC -name '*Fuzzer.java'); do
  fuzzer_basename=$(basename -s .java $fuzzer)
  echo $fuzzer
  javac -cp $BUILD_CLASSPATH $fuzzer
  cp $SRC/$fuzzer_basename.class $OUT/
  
  # Create an execution wrapper that executes Jazzer with the correct arguments.
  echo "#!/bin/bash
# LLVMFuzzerTestOneInput for fuzzer detection.
this_dir=\$(dirname \"\$0\")
if [[ \"\$@\" =~ (^| )-runs=[0-9]+($| ) ]]; then
  mem_settings='-Xmx1900m:-Xss900k'
else
  mem_settings='-Xmx2048m:-Xss1024k'
fi
LD_LIBRARY_PATH=\"${JVM_LD_LIBRARY_PATH}\":\$this_dir \
\$this_dir/jazzer_driver --agent_path=\$this_dir/jazzer_agent_deploy.jar \
--cp=${RUNTIME_CLASSPATH}:${OUT}/${fuzzer_basename}.class \
--target_class=${fuzzer_basename} \
--jvm_args=\"\$mem_settings:-Djava.awt.headless=true\" \
\$@" > ${OUT}/${fuzzer_basename}
  chmod +x ${OUT}/${fuzzer_basename}

done

# attempt to cleanup classpath issues
# ---- Compile all *Fuzzer.java and create wrappers ----
set -euo pipefail

# 0) Find all fuzzer sources
mapfile -t FUZZ_SOURCES < <(find "$SRC" -type f -name '*Fuzzer.java' | sort)
if [[ ${#FUZZ_SOURCES[@]} -eq 0 ]]; then
  echo "ERROR: No *Fuzzer.java files found under \$SRC" >&2
  exit 1
fi
echo "Found fuzzers:"; printf '  - %s\n' "${FUZZ_SOURCES[@]}"

# 1) Build-time classpath: Jazzer API + everything already in /out
COMP_CP="$JAZZER_API_PATH"
if compgen -G "/out/*.jar" > /dev/null; then
  COMP_CP="$COMP_CP:$(printf "%s:" /out/*.jar)"
fi

# -------------------------
# Step 2: build the fuzzers
# -------------------------
set -euo pipefail

# Find all fuzzer sources
mapfile -t FUZZ_SOURCES < <(find "$SRC" -type f -name '*Fuzzer.java' | sort)
if [[ ${#FUZZ_SOURCES[@]} -eq 0 ]]; then
  echo "ERROR: No *Fuzzer.java files found under \$SRC" >&2
  exit 1
fi
echo "Found fuzzers:"; printf '  - %s\n' "${FUZZ_SOURCES[@]}"

# Build-time classpath: Jazzer API + every jar we already copied into /out
COMP_CP="$JAZZER_API_PATH"
if compgen -G "/out/*.jar" > /dev/null; then
  COMP_CP="$COMP_CP:$(printf "%s:" /out/*.jar)"
fi

# Compile ALL fuzzers to a temp dir and jar them (no loose .class on --cp)
rm -rf /tmp/fuzzbuild && mkdir -p /tmp/fuzzbuild
javac -cp "$COMP_CP" -d /tmp/fuzzbuild "${FUZZ_SOURCES[@]}"
jar cf /out/fuzzers.jar -C /tmp/fuzzbuild .

# Helper to emit one wrapper per fuzzer class
make_wrapper() {
  local fqcn="$1"
  local exe="$2"   # wrapper filename under /out

  cat > "/out/${exe}" <<'EOF'
#!/bin/bash
set -euo pipefail
this_dir="$(cd "$(dirname "$0")" && pwd)"

# Smaller mem for -runs=N one-shots
if [[ " $* " == *" -runs="* ]]; then
  mem='-Xmx1900m:-Xss900k'
else
  mem='-Xmx2048m:-Xss1024k'
fi

# Runtime CP must contain directories/jars (NOT single .class files)
runtime_cp="$this_dir:$this_dir/fuzzers.jar"
for j in "$this_dir"/*.jar; do
  [[ -e "$j" ]] && runtime_cp="${runtime_cp}:${j}"
done

LD_LIBRARY_PATH="${JVM_LD_LIBRARY_PATH}:$this_dir" \
"$this_dir/jazzer_driver" \
  --agent_path="$this_dir/jazzer_agent_deploy.jar" \
  --cp="$runtime_cp" \
  --target_class=__FQCN__ \
  --jvm_args="$mem:-Djava.awt.headless=true" \
  "$@"
EOF
  sed -i "s#__FQCN__#${fqcn}#g" "/out/${exe}"
  chmod +x "/out/${exe}"
}

# Derive FQCNs and create wrappers
for src in "${FUZZ_SOURCES[@]}"; do
  CLASS_BASENAME="$(basename "$src" .java)"     # e.g., MachHeaderFuzzer
  PKG_LINE=$(grep -m1 '^package ' "$src" || true)
  if [[ -n "$PKG_LINE" ]]; then
    PKG=$(sed -E 's/^package[[:space:]]+([^;]+);/\1/' <<<"$PKG_LINE")
    FQCN="${PKG}.${CLASS_BASENAME}"
  else
    FQCN="${CLASS_BASENAME}"
  fi
  make_wrapper "$FQCN" "$CLASS_BASENAME"
  echo "Created /out/${CLASS_BASENAME} -> --target_class=${FQCN}"
done

# Optional sanity: should execute (or throw from your code), not "not found"
for exe in /out/*Fuzzer; do
  echo "Sanity: $exe -runs=1"
  "$exe" -runs=1 || true
done
