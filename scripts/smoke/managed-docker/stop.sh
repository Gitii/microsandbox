#!/bin/bash
set -euo pipefail
# This runs only after the real Docker daemon has stopped.
if pgrep -x dockerd; then exit 1; fi
if test -e /var/lib/docker/volumes/proof-hang; then sleep 180; fi
sleep 3
printf 'docker-stopped-after-delay\n' >> /var/lib/docker/volumes/proof-stop
sync
