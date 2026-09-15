#!/bin/bash
set -euo pipefail
vol=/var/lib/docker/volumes
case ${1:?phase} in
ready)
    for i in $(seq 1 30); do
        test "$(cat /proc/1/comm)" = systemd && break
        sleep 1
    done
    test "$(cat /proc/1/comm)" = systemd
    test "$(findmnt -n -o FSTYPE /run)" = tmpfs
    test "$(readlink -f /var/run)" = /run
    test "$(findmnt -n -o FSTYPE /var/lib/docker)" = ext4
    mountpoint -q "$vol"
    for i in $(seq 1 90); do
        if docker info >/dev/null 2>&1; then break; fi
        sleep 1
    done
    docker version --format '{{.Server.Version}}' | grep '^29\.'
    test "$(docker info --format '{{.Driver}}')" = overlay2
    test "$(docker info --format '{{.DockerRootDir}}')" = /var/lib/docker
    test "$(findmnt -n -o TARGET -T /var/lib/docker/containerd)" = /var/lib/docker
    docker import /opt/native.tar docker-runtime-native
    docker run --rm docker-runtime-native /bin/busybox uname -m
    if test "$(uname -m)" != x86_64; then
        docker import --platform linux/amd64 /opt/amd64.tar docker-runtime-amd64
        test "$(docker run --rm --platform linux/amd64 -v /usr/bin/qemu-x86_64-static:/qemu:ro docker-runtime-amd64 /qemu /bin/busybox uname -m)" = x86_64
    fi
    ;;
seed)
    docker volume create --label proof=named named
    docker volume create --label proof=empty empty
    docker volume create --label proof=cache cache
    docker volume create --label proof=options --opt type=tmpfs --opt device=tmpfs --opt o=size=1m options
    docker volume create --label proof=delete deleted
    docker volume rm deleted
    anonymous=$(docker volume create --label proof=anonymous)
    printf '%s' "$anonymous" > "$vol/proof-anonymous"
    for name in named cache "$anonymous"; do
        docker run --rm -v "$name:/data" docker-runtime-native /bin/sh -c 'echo retained > /data/payload; /bin/busybox chmod 640 /data/payload; /bin/busybox chown 123:456 /data/payload'
    done
    docker run --rm -v options:/cache docker-runtime-native /bin/sh -c 'echo transient > /cache/payload'
    test -s "$vol/metadata.db"
    test -s "$vol/options/opts.json"
    docker volume inspect named empty cache options "$anonymous" > "$vol/proof-inspect.json"
    cat "$vol/options/opts.json" > "$vol/proof-opts.json"
    touch /var/lib/docker/working-only
    touch /run/proof-ephemeral
    ;;
verify)
    test ! -e /var/lib/docker/working-only
    test ! -e /run/proof-ephemeral
    test "$(cat "$vol/proof-stop")" = docker-stopped-after-delay
    anonymous=$(cat "$vol/proof-anonymous")
    docker volume inspect named empty cache options "$anonymous" > /tmp/inspect.json
    cmp "$vol/proof-inspect.json" /tmp/inspect.json
    cmp "$vol/proof-opts.json" "$vol/options/opts.json"
    ! docker volume inspect deleted
    test -s "$vol/metadata.db"
    for name in named cache "$anonymous"; do
        docker run --rm -v "$name:/data" docker-runtime-native /bin/sh -c 'test "$(/bin/busybox cat /data/payload)" = retained; test "$(/bin/busybox stat -c %a:%u:%g /data/payload)" = 640:123:456'
    done
    docker run --rm -v empty:/data docker-runtime-native /bin/sh -c 'test -z "$(/bin/busybox ls -A /data)"'
    docker run --rm -v options:/cache docker-runtime-native /bin/sh -c 'test ! -e /cache/payload; /bin/busybox grep " /cache tmpfs " /proc/mounts'
    ;;
*) exit 2;;
esac
