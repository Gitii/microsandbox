#!/bin/bash
set -euo pipefail
out=${1:?usage: build.sh ABSOLUTE-OUTPUT-DIRECTORY}
[[ $out = /* && $(basename "$out") = docker-runtime-* ]] || exit 2
mkdir -p "$out"
name="docker-runtime-fixture-$(date +%s)-$$"
docker build --quiet -t "$name" "$(dirname "$0")"
container=$(docker create --name "$name-export" "$name")
trap 'docker rm -f "$container" >/dev/null' EXIT
docker export -o "$out/rootfs.tar" "$container"
docker run --rm --name "$name-format" -v "$out:/out" --entrypoint /bin/bash "$name" -c '
set -euo pipefail
mkdir /tmp/rootfs
tar -xf /out/rootfs.tar -C /tmp/rootfs
rm -f /tmp/rootfs/.dockerenv
truncate -s 3G /out/rootfs.ext4
mkfs.ext4 -q -F -d /tmp/rootfs /out/rootfs.ext4
chmod 666 /out/rootfs.ext4
'
printf '%s\n' "$name" > "$out/image-name"
printf 'Fixture root: %s/rootfs.ext4\n' "$out"
