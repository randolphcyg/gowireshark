ARG WIRESHARK_VER=4.6.3
ARG PCAP_VER=1.10.6
ARG GO_VER=1.25.6
ARG CJSON_VER=1.7.19
ARG CHASH_VER=2.3.0

# =============================================================================
# Stage 1: DLL Builder
# =============================================================================
FROM ubuntu:24.04 AS dll-builder
ARG WIRESHARK_VER
ARG PCAP_VER
ARG CJSON_VER
ARG CHASH_VER

RUN sed -i 's@//.*archive.ubuntu.com@//mirrors.aliyun.com@g' /etc/apt/sources.list.d/ubuntu.sources && \
    sed -i 's@//.*security.ubuntu.com@//mirrors.aliyun.com@g' /etc/apt/sources.list.d/ubuntu.sources && \
    sed -i 's@//ports.ubuntu.com@//mirrors.aliyun.com@g' /etc/apt/sources.list.d/ubuntu.sources

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential gcc-multilib cmake ninja-build wget \
    flex bison doxygen \
    libpcap-dev libglib2.0-dev libssl-dev libc-ares-dev \
    libgcrypt20-dev libspeexdsp-dev libgmp-dev libunbound-dev \
    libxml2-dev libsasl2-dev libzstd-dev libcurl4-openssl-dev ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /opt

# Build Wireshark
RUN wget https://www.wireshark.org/download/src/wireshark-${WIRESHARK_VER}.tar.xz -L --no-check-certificate && \
    tar -xf wireshark-${WIRESHARK_VER}.tar.xz && \
    mv wireshark-${WIRESHARK_VER} wireshark
WORKDIR /opt/wireshark/build
RUN cmake -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_wireshark=OFF \
    -DENABLE_LUA=OFF \
    -DDISABLE_PROTOBUF=ON \
    -DENABLE_DEBUG_INFO=OFF \
    -DENABLE_MAN_PAGES=OFF \
    -DDISABLE_GNUTLS=ON \
    -DENABLE_DOCS=OFF \
    -DENABLE_APPLICATION_BUNDLE=OFF \
    -DCMAKE_INSTALL_PREFIX=/opt/wireshark/build .. && \
    ninja -j$(nproc) && \
    ninja install

# Build Libpcap
WORKDIR /opt
RUN wget http://www.tcpdump.org/release/libpcap-${PCAP_VER}.tar.gz --no-check-certificate && \
    tar -zxvf libpcap-${PCAP_VER}.tar.gz && \
    cd libpcap-${PCAP_VER} && \
    ./configure && \
    make && \
    mv libpcap.so.${PCAP_VER} libpcap.so.1

WORKDIR /app/pkg
RUN wget https://raw.githubusercontent.com/DaveGamble/cJSON/v${CJSON_VER}/cJSON.c && \
    wget https://raw.githubusercontent.com/DaveGamble/cJSON/v${CJSON_VER}/cJSON.h && \
    wget https://raw.githubusercontent.com/troydhanson/uthash/v${CHASH_VER}/src/uthash.h

RUN mkdir -p /app/libs /app/include/wireshark

RUN cp -d /opt/wireshark/build/run/lib*.so* /app/libs/ && \
    cp /opt/libpcap-${PCAP_VER}/libpcap.so.1 /app/libs/ && \
    ln -sf /app/libs/libpcap.so.1 /app/libs/libpcap.so

RUN cp /opt/wireshark/*.h /app/include/wireshark/ && \
    cp /opt/wireshark/build/*.h /app/include/wireshark/ && \
    cp -r /opt/wireshark/include/* /app/include/wireshark/ && \
    cp -r /opt/wireshark/epan /app/include/wireshark/ && \
    cp -r /opt/wireshark/wiretap /app/include/wireshark/ && \
    cp -r /opt/wireshark/wsutil /app/include/wireshark/

RUN cp /opt/libpcap-${PCAP_VER}/*.h /app/include/

RUN rm -rf /opt/*.tar.* /var/tmp/*

# =============================================================================
# Stage 2: Go Builder
# =============================================================================
FROM ubuntu:24.04 AS go-builder
ARG GO_VER

RUN sed -i 's@//.*archive.ubuntu.com@//mirrors.aliyun.com@g' /etc/apt/sources.list.d/ubuntu.sources && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
    wget ca-certificates build-essential pkg-config \
    libglib2.0-dev \
    libpcap-dev \
    libssl-dev \
    libzstd-dev \
    libsasl2-dev \
    libxml2-dev \
    libc-ares-dev \
    libcurl4-openssl-dev && \
    rm -rf /var/lib/apt/lists/*

RUN wget https://go.dev/dl/go${GO_VER}.linux-amd64.tar.gz --no-check-certificate && \
    tar -C /usr/local -xzf go${GO_VER}.linux-amd64.tar.gz && \
    rm go${GO_VER}.linux-amd64.tar.gz

ENV PATH="/usr/local/go/bin:${PATH}" \
    CGO_ENABLED=1 \
    GOPROXY=https://goproxy.cn,direct \
    CGO_CFLAGS="-I/app/include -I/app/include/wireshark -I/app/include/wireshark/epan -I/app/include/wireshark/wiretap -I/app/include/wireshark/wsutil" \
    CGO_LDFLAGS="-L/app/libs -Wl,-rpath,/app/libs -lwiretap -lwsutil -lwireshark -lpcap -lglib-2.0"

COPY --from=dll-builder /app/libs/ /app/libs/
COPY --from=dll-builder /app/include/ /app/include/

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY --from=dll-builder /app/pkg/ ./pkg/
COPY . .

RUN go build -trimpath -ldflags="-s -w" -o /app/gowireshark ./cmd/main.go

# =============================================================================
# Stage 3: Runtime
# =============================================================================
FROM ubuntu:24.04 AS runtime
ENV TZ=Asia/Shanghai DEBIAN_FRONTEND=noninteractive

RUN sed -i 's@//.*archive.ubuntu.com@//mirrors.aliyun.com@g' /etc/apt/sources.list.d/ubuntu.sources && \
    sed -i 's@//.*security.ubuntu.com@//mirrors.aliyun.com@g' /etc/apt/sources.list.d/ubuntu.sources && \
    sed -i 's@//ports.ubuntu.com@//mirrors.aliyun.com@g' /etc/apt/sources.list.d/ubuntu.sources

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    libpcap0.8 libc-ares2 libglib2.0-0 libgcrypt20 libxml2 openssl \
    libsasl2-2 libzstd1 libcurl4 ca-certificates tzdata && \
    ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

COPY --from=go-builder /app/gowireshark /app/gowireshark
COPY --from=dll-builder /app/libs/ /app/libs/

ENV LD_LIBRARY_PATH=/app/libs
WORKDIR /app
EXPOSE 8090
ENTRYPOINT ["/app/gowireshark"]