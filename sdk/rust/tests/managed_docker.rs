//! Real managed Docker proof. See scripts/smoke/managed-docker/README.md.
//! The explicit runner requires prerequisites and executes the ignored test.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use microsandbox::Sandbox;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn prerequisite(name: &str) -> PathBuf {
    let path = PathBuf::from(std::env::var(name).unwrap_or_else(|_| panic!("set {name}")));
    assert!(
        path.is_absolute() && path.is_file(),
        "invalid {name}: {path:?}"
    );
    path
}

async fn boot(name: &str, root: &Path, working: &Path, retained: Option<&Path>) -> Sandbox {
    let mut builder = Sandbox::builder(name)
        .image(root.to_path_buf())
        .init("/sbin/init")
        .cpus(2)
        .memory(2048)
        .volume("/var/lib/docker", |mount| {
            mount.disk(working).fstype("ext4")
        });
    if let Some(retained) = retained {
        builder = builder.volume("/var/lib/docker/volumes", |mount| {
            mount.disk(retained).fstype("ext4")
        });
    }
    builder.create().await.expect("boot managed Docker VM")
}

async fn shell(sandbox: &Sandbox, command: &str) -> String {
    eprintln!("Guest proof: {command}");
    let output = sandbox
        .shell_with(command, |exec| exec.timeout(Duration::from_secs(110)))
        .await
        .expect("guest exec");
    if !output.status().success {
        let diagnostic = sandbox.shell("cat /proc/1/comm; cat /proc/mounts; systemctl status docker containerd --no-pager; journalctl -b -u docker -u containerd --no-pager; ps aux").await;
        match diagnostic {
            Ok(output) => eprintln!(
                "Guest diagnostics:\n{}\n{}",
                output.stdout().unwrap_or_default(),
                output.stderr().unwrap_or_default()
            ),
            Err(error) => eprintln!("Guest diagnostics unavailable: {error}"),
        }
    }
    assert!(
        output.status().success,
        "{command}: stdout={} stderr={}",
        output.stdout().unwrap_or_default(),
        output.stderr().unwrap_or_default()
    );
    output.stdout().expect("UTF-8").to_owned()
}

async fn stop(sandbox: Sandbox, name: &str) {
    sandbox.detach().await;
    let handle = Sandbox::get(name).await.expect("get for stop");
    let started = Instant::now();
    let result = handle.stop_with_timeout(Duration::from_secs(150)).await;
    assert!(
        started.elapsed() >= Duration::from_secs(3),
        "stop returned before delayed service marker"
    );
    let home = PathBuf::from(std::env::var("MSB_HOME").unwrap());
    let console =
        std::fs::read_to_string(home.join("sandboxes").join(name).join("logs/kernel.log"))
            .expect("poweroff console");
    std::fs::write(home.join("poweroff.log"), &console).expect("retain poweroff evidence");
    result.expect("graceful service shutdown; inspect MSB_HOME/poweroff.log");
    // The kernel's own message for a completed kernel_power_off(): systemd's
    // "Powering off." status line is not guaranteed to reach the console.
    assert!(
        console.contains("reboot: Power down"),
        "missing kernel poweroff: {console}"
    );
    assert!(
        !console.contains("Restarting system")
            && !console.contains("Rebooting.")
            && !console.contains("System halted instead"),
        "guest did not power off: {console}"
    );
    eprintln!(
        "PASS real service stop and poweroff console after {:?}",
        started.elapsed()
    );
    handle.remove().await.expect("remove stopped sandbox");
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
#[ignore = "real current-source runtime and Debian Docker29 fixture; run scripts/smoke/managed-docker/run.sh"]
async fn managed_docker_retains_complete_volumes_and_reports_shutdown_failure() {
    let binary = prerequisite("MSB_PATH");
    prerequisite("MSB_LIBKRUNFW_PATH");
    let fixture = prerequisite("MSB_DOCKER_PROOF_ROOT");
    let home = PathBuf::from(std::env::var("MSB_HOME").expect("use the isolated run.sh runner"));
    assert!(
        home.is_absolute()
            && home
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("docker-runtime-")
    );
    assert_eq!(microsandbox::config::resolve_msb_path().unwrap(), binary);
    #[cfg(target_os = "linux")]
    assert!(Path::new("/dev/kvm").exists(), "real Linux KVM required");
    let directory = tempfile::Builder::new()
        .prefix("docker-runtime-")
        .tempdir_in(&home)
        .unwrap()
        .keep();
    eprintln!("Proof disk artifacts: {}", directory.display());
    let root = directory.join("root.raw");
    std::fs::copy(fixture, &root).expect("private writable root image");
    let working = directory.join("working.raw");
    let retained = directory.join("retained.raw");
    microsandbox::disk::create(&working, 2 * 1024 * 1024 * 1024).unwrap();
    microsandbox::disk::create(&retained, 512 * 1024 * 1024).unwrap();
    let name = format!("docker-runtime-{}", std::process::id());

    let first = boot(&name, &root, &working, Some(&retained)).await;
    eprintln!(
        "{}",
        shell(&first, "bash -x /usr/local/bin/docker-runtime-proof ready").await
    );
    shell(&first, "/usr/local/bin/docker-runtime-proof seed").await;
    shell(
        &first,
        "test $(id -u) = 0; test $(awk '/^Uid:/{print $2}' /proc/$PPID/status) = 0",
    )
    .await;
    let nonroot = first
        .shell_with("test $(id -u) = 1000; test -t 1", |exec| {
            exec.user("proof").tty(true)
        })
        .await
        .unwrap();
    assert!(
        nonroot.status().success,
        "non-root PTY failed: {:?}",
        nonroot.stderr()
    );
    shell(
        &first,
        "curl --fail --max-time 30 https://example.com/ >/dev/null",
    )
    .await;
    first.metrics().await.expect("live sandbox metrics");
    #[cfg(feature = "ssh")]
    {
        let ssh = first.ssh().open_client().await.expect("SSH connection");
        let output = ssh
            .exec_with("test -t 1; id -u", |exec| exec.tty(true))
            .await
            .unwrap();
        assert_eq!(output.status, 0);
        assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "0");
        ssh.close().await.unwrap();
    }
    stop(first, &name).await;
    std::fs::remove_file(&working).expect("delete working disk only after stop");
    microsandbox::disk::create(&working, 2 * 1024 * 1024 * 1024).unwrap();

    let second = boot(&name, &root, &working, Some(&retained)).await;
    shell(&second, "bash -x /usr/local/bin/docker-runtime-proof ready").await;
    shell(&second, "/usr/local/bin/docker-runtime-proof verify").await;
    stop(second, &name).await;
    eprintln!(
        "PASS complete volumes identity/metadata/options/data/modes after working disk replacement"
    );

    let missing = boot(&name, &root, &working, None).await;
    shell(&missing, "for i in $(seq 1 30); do systemctl is-failed docker.service && break; sleep 1; done; ! docker info; ! mountpoint -q /var/lib/docker/volumes; systemctl is-failed docker.service").await;
    missing.stop().await.expect("stop missing-mount VM");
    Sandbox::remove(&name).await.unwrap();
    eprintln!("PASS missing retained mount fails Docker readiness");

    let hung = boot(&name, &root, &working, Some(&retained)).await;
    shell(&hung, "bash -x /usr/local/bin/docker-runtime-proof ready").await;
    shell(&hung, "touch /var/lib/docker/volumes/proof-hang").await;
    hung.detach().await;
    let handle = Sandbox::get(&name).await.unwrap();
    let started = Instant::now();
    let result = handle.stop_with_timeout(Duration::from_secs(150)).await;
    assert!(
        result.is_err(),
        "host shutdown deadline must not report success"
    );
    assert!(
        started.elapsed() >= Duration::from_secs(120),
        "failure happened before VMM service deadline: {result:?}"
    );
    eprintln!("PASS shutdown deadline reports failure: {result:?}");
    handle.kill().await.ok();
    handle.remove().await.unwrap();
}
