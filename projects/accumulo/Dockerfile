# Base JVM builder from OSS-Fuzz
FROM gcr.io/oss-fuzz-base/base-builder-jvm

# Install Maven + tools
RUN apt-get update && apt-get install -y --no-install-recommends \
      maven curl unzip ca-certificates git python3 make autoconf automake libtool \
  && rm -rf /var/lib/apt/lists/*

# Pull Accumulo (use a stable LTM tag/branch; 2.1.x is current LTM)
# You can also pin to a commit if you prefer.
RUN git clone --depth 1 --single-branch --branch rel/2.1.4 \
      https://github.com/apache/accumulo.git $SRC/accumulo

# Copy your fuzzer(s) + build script
COPY ColumnVisibilityFuzzer.java $SRC/
COPY build.sh $SRC/
WORKDIR $SRC

