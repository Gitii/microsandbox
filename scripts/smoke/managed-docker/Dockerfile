FROM --platform=linux/amd64 debian:bookworm AS amd64
RUN apt-get update && apt-get install -y --no-install-recommends busybox-static && \
    mkdir -p /opt/amd64/bin && cp /bin/busybox /opt/amd64/bin/busybox && \
    ln -s busybox /opt/amd64/bin/sh && tar -C /opt/amd64 -cf /opt/amd64.tar .

FROM debian:bookworm
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends systemd systemd-sysv ca-certificates curl gnupg iptables iproute2 util-linux e2fsprogs busybox-static python3 procps && \
    install -m 0755 -d /etc/apt/keyrings && \
    curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc && \
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian bookworm stable" > /etc/apt/sources.list.d/docker.list && \
    apt-get update && apt-get install -y --no-install-recommends 'docker-ce=5:29.*' 'docker-ce-cli=5:29.*' containerd.io && \
    rm -rf /var/lib/apt/lists/* && useradd -m -u 1000 proof
RUN mkdir -p /etc/docker /etc/systemd/system/docker.service.d /var/lib/docker/volumes /opt/native/bin && \
    cp /bin/busybox /opt/native/bin/busybox && ln -s busybox /opt/native/bin/sh && \
    tar -C /opt/native -cf /opt/native.tar . && rm -rf /opt/native && \
    printf '%s\n' '{"storage-driver":"overlay2","features":{"containerd-snapshotter":false}}' > /etc/docker/daemon.json && \
    systemctl enable docker.service && systemctl mask systemd-networkd-wait-online.service
RUN mkdir -p /etc/containerd && printf '%s\n' 'version = 2' 'root = "/var/lib/docker/containerd"' 'state = "/run/containerd"' > /etc/containerd/config.toml
RUN if [ "$(dpkg --print-architecture)" != amd64 ]; then \
      apt-get update && apt-get install -y --no-install-recommends qemu-user-static && rm -rf /var/lib/apt/lists/*; \
    fi
COPY docker-proof.conf /etc/systemd/system/docker.service.d/proof.conf
COPY stop.sh /usr/local/bin/docker-runtime-stop
COPY proof.sh /usr/local/bin/docker-runtime-proof
COPY --from=amd64 /opt/amd64.tar /opt/amd64.tar
RUN chmod 755 /usr/local/bin/docker-runtime-* && \
    ln -sf /lib/systemd/system/multi-user.target /etc/systemd/system/default.target
CMD ["/sbin/init"]
