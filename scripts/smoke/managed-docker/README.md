# Managed Docker runtime proof

This boots real KVM VMs with Debian systemd and Docker Engine 29 using `overlay2`.
Docker's full `/var/lib/docker/volumes` directory is a retained ext4 submount
inside a disposable ext4 `/var/lib/docker` working disk. The test deletes and
recreates the working disk only after successful graceful shutdown.

Build the fixture using the host Docker engine:

```sh
bash scripts/smoke/managed-docker/build.sh /tmp/docker-runtime-fixture
```

Build current-source `msb`, `agentd`, and kernel with the repository's `just`
tooling, then explicitly select those artifacts. Run from the repository root:

```sh
env MSB_PATH="$PWD/build/msb" \
    MSB_LIBKRUNFW_PATH="/absolute/path/to/current-source/libkrunfw.so" \
    MSB_DOCKER_PROOF_ROOT=/tmp/docker-runtime-fixture/rootfs.ext4 \
    bash scripts/smoke/managed-docker/run.sh
```

The test is ignored during ordinary workspace tests; the runner explicitly
executes it with `--ignored`, and missing prerequisites fail. The runner
creates isolated `docker-runtime-*` state under `TMPDIR` (default `/tmp/opencode`), preserves diagnostics, and prints its
location. Fixture image names are unique; no host Docker daemon configuration is
changed. The guest imports its bundled native BusyBox image without a registry.
HTTPS regression coverage uses `https://example.com`.

Assertions cover named, anonymous, empty, retained filesystem cache and option-bearing volume identity,
labels, Docker metadata (including `metadata.db` and `opts.json`), retained file
data, ownership and modes, native containers, missing-submount readiness failure,
root agent and non-root PTY execution, HTTPS, SSH and metrics. A real Docker
`ExecStopPost` waits three seconds before writing a retained shutdown marker.
A final injected 180-second service stop must exceed the 120-second VMM deadline
and surface as SDK failure, not successful shutdown. Console checks require
systemd poweroff and reject reboot or halt-instead-of-poweroff. On ARM64 the
fixture also runs the bundled static amd64 container through explicit
`qemu-x86_64-static` user-mode emulation.
