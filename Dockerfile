ARG WIRESHARK_VER=4.4.9
ARG PCAP_VER=1.10.5
ARG GO_VER=1.25.1

# build Wireshark libpcap
FROM ubuntu:24.04 AS dll-builder
ARG WIRESHARK_VER
ARG PCAP_VER

# dep
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    gcc-multilib \
    cmake \
    ninja-build \
    wget \
    libpcap-dev \
    libglib2.0-dev \
    libssl-dev \
    libc-ares-dev \
    libgcrypt20-dev \
    libspeexdsp-dev \
    libgmp-dev \
    libunbound-dev \
    flex \
    bison \
    doxygen && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /opt
RUN wget https://1.as.dl.wireshark.org/src/wireshark-${WIRESHARK_VER}.tar.xz --no-check-certificate && \
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
    -DCMAKE_INSTALL_PREFIX=/opt/wireshark/build .. && \
    ninja -j$(nproc) && \
    ninja install

WORKDIR /opt
RUN wget  http://www.tcpdump.org/release/libpcap-${PCAP_VER}.tar.gz --no-check-certificate && \
    tar -zxvf libpcap-${PCAP_VER}.tar.gz && \
    cd libpcap-${PCAP_VER} && \
    ./configure && \
    make && \
    mv libpcap.so.${PCAP_VER} libpcap.so.1

RUN rm -rf \
    /opt/wireshark-${WIRESHARK_VER}.tar.xz \
    /opt/wireshark/doc \
    /opt/wireshark/test \
    /opt/libpcap-${PCAP_VER}.tar.gz \
    /var/lib/apt/lists/* \
    /tmp/* \
    /var/tmp/*

# build service
FROM ubuntu:24.04 AS go-builder
ARG GO_VER
ARG PCAP_VER

# dep
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    pkg-config \
    libglib2.0-dev \
    libpcap-dev \
    libxml2-dev \
    libc-ares-dev \
    libssl-dev \
    libgcrypt20-dev \
    gcc \
    wget \
    ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Go
RUN wget https://go.dev/dl/go${GO_VER}.linux-amd64.tar.gz --no-check-certificate && \
    tar -C /usr/local -xzf go${GO_VER}.linux-amd64.tar.gz && \
    rm go${GO_VER}.linux-amd64.tar.gz
ENV PATH="/usr/local/go/bin:${PATH}"

RUN mkdir -p /gowireshark/{include/wireshark,libs}

# dll
COPY --from=dll-builder \
    /opt/wireshark/build/run/libwireshark.so.18 \
    /opt/wireshark/build/run/libwiretap.so.15 \
    /opt/wireshark/build/run/libwsutil.so.16 \
    /opt/libpcap-${PCAP_VER}/libpcap.so.1 \
    /gowireshark/libs/
# ln
RUN cd /gowireshark/libs && \
    ln -s libwireshark.so.18 libwireshark.so && \
    ln -s libwiretap.so.15 libwiretap.so && \
    ln -s libwsutil.so.16 libwsutil.so && \
    ldconfig

# sub mod
COPY --from=dll-builder /opt/wireshark/epan/ /gowireshark/include/wireshark/epan/
COPY --from=dll-builder /opt/wireshark/wsutil/ /gowireshark/include/wireshark/wsutil/
COPY --from=dll-builder /opt/wireshark/wiretap/ /gowireshark/include/wireshark/wiretap/
# include
COPY --from=dll-builder /opt/wireshark/include/* /gowireshark/include/wireshark/
# header files
COPY --from=dll-builder /opt/wireshark/cfile.h \
                        /opt/wireshark/build/ws_version.h \
                        /opt/wireshark/build/config.h \
                        /opt/wireshark/frame_tvbuff.h \
                        /gowireshark/include/wireshark/
# frame_tvbuff
COPY --from=dll-builder /opt/wireshark/frame_tvbuff.c /gowireshark/frame_tvbuff.c
# libpcap
COPY --from=dll-builder /opt/libpcap-${PCAP_VER}/pcap/ /gowireshark/libs/pcap/

# set ENV
ENV CGO_ENABLED=1 \
    GOPROXY=https://goproxy.cn,direct \
    CGO_LDFLAGS="-L/gowireshark/libs -Wl,-rpath=/gowireshark/libs -lwsutil -lwiretap -lwireshark -lpcap -lglib-2.0 -lgcrypt" \
    PKG_CONFIG_PATH=/usr/lib/x86_64-linux-gnu/pkgconfig:/gowireshark/libs/pkgconfig \
    CGO_CFLAGS="-I/gowireshark/include -I/gowireshark/include/wireshark" \
    LD_LIBRARY_PATH=/gowireshark/libs

WORKDIR /gowireshark
COPY go.mod go.sum ./
RUN update-ca-certificates && \
    go mod download
COPY . .
RUN go build -trimpath -ldflags="-s -w" -o /gowireshark/parser cmd/main.go && \
    rm -rf /usr/local/go/pkg /root/.cache/go-build

# runtime
FROM ubuntu:24.04 AS runtime

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    libpcap0.8 \
    libc-ares2 \
    libglib2.0-0 \
    libgcrypt20 \
    libxml2 \
    openssl \
    tzdata && \
    ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime && \
    apt-get clean && \
    rm -rf \
        /var/lib/apt/lists/* \
        /usr/share/doc/* \
        /usr/share/man/* \
        /tmp/* \
        /var/tmp/*

COPY --from=go-builder /gowireshark/parser /gowireshark/parser
COPY --from=go-builder /gowireshark/libs/ /gowireshark/libs/

ENV LD_LIBRARY_PATH=/gowireshark/libs:/usr/lib/x86_64-linux-gnu \
    TZ=Asia/Shanghai

WORKDIR /gowireshark
EXPOSE 8090
ENTRYPOINT ["/gowireshark/parser"]