#!/bin/bash
set -euo pipefail
: "${MSB_PATH:?set absolute path to current-source build/msb}"
: "${MSB_LIBKRUNFW_PATH:?set absolute path to current-source firmware}"
: "${MSB_DOCKER_PROOF_ROOT:?run build.sh and set its rootfs.ext4 path}"
export MSB_HOME
MSB_HOME=$(mktemp -d "${TMPDIR:-/tmp}/docker-runtime-home-XXXXXX")
printf 'Proof state and logs: %s\n' "$MSB_HOME"
devbox run -- cargo test -p microsandbox --features ssh --test managed_docker -- --ignored --nocapture 2>&1 | tee "$MSB_HOME/proof.log"
