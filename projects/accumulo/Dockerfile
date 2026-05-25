FROM gcr.io/oss-fuzz-base/base-builder-jvm

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    git zip unzip maven ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN git clone https://github.com/apache/accumulo $SRC/accumulo && \
    cd $SRC/accumulo && \
    git checkout f88500dfd02683d6497467fe73006a2a739ab47f

COPY build.sh *.java *.dict *.options *_seed_corpus.zip $SRC/
WORKDIR $SRC/accumulo
