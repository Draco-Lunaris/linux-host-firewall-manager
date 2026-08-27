//! Containerized UFW/firewalld backend integration tests (AGENTS.md follow-up #4).
//!
//! The agent's `apply` path runs `ufw --force reset` + replay, which must never
//! execute on a real host from a test — so the real tooling is exercised inside
//! throwaway containers with their own network namespace (iptables/nftables
//! rules are per-netns; `--cap-add=NET_ADMIN` is enough).
//!
//! The file is dual-mode:
//!
//! - **Outer (host, default):** skipped unless `LHFM_CONTAINER_ITEST=1`, so
//!   `just check` and CI's regular test job stay fast and hermetic. The outer
//!   test builds `scripts/itest/Dockerfile.{ufw,firewalld}`, runs the compiled
//!   test binary inside the container in inner mode, and asserts the inner
//!   suite passed. `just itest` is the entry point.
//!
//! - **Inner (in container):** tests run for real when `LHFM_ITEST_INNER=1`
//!   (set by the outer harness via `docker run -e`); on the host they are
//!   no-ops. They drive `UfwBackend` / `FirewalldBackend` against the live
//!   tooling: full apply (reset → umbilical → defaults → rules), default-policy
//!   status parsing, umbilical presence under deny/deny, snapshot-hash
//!   convergence, and reset.

use fw_agent::backend::{ApplyContext, FirewallBackend, FirewalldBackend, UfwBackend};
use fw_core::models::{FirewallAction, FirewallDirection, FirewallProtocol, FirewallRule};
use std::process::{Command, Output};
use std::time::{Duration, Instant};

// ── Outer harness ────────────────────────────────────────────────────────

const UFW_SUITE: &[&str] = &[
    "it_ufw_apply_deny_deny_umbilical_and_status",
    "it_ufw_reapply_converges_same_snapshot_hash",
    "it_ufw_null_defaults_leave_previous_policies_sticky",
    "it_ufw_reset_deactivates",
];

const FIREWALLD_SUITE: &[&str] = &[
    "it_firewalld_apply_rich_rules_and_snapshot",
    "it_firewalld_reset_clears_rules",
];

/// Build one itest image and run its inner test suite in a fresh container.
fn run_suite(dockerfile: &str, tag: &str, tests: &[&str]) {
    let repo_root = env!("CARGO_MANIFEST_DIR")
        .rsplit_once("/crates")
        .map(|(root, _)| root.to_string())
        .expect("CARGO_MANIFEST_DIR should live under <repo>/crates/fw-agent");

    // Build (cached by BuildKit cache mounts; -q keeps logs readable).
    let build = docker_with_timeout(
        1800,
        &[
            "build",
            "-q",
            "-t",
            tag,
            "-f",
            &format!("scripts/itest/{dockerfile}"),
            ".",
        ],
        &repo_root,
        "docker build",
    )
    .expect("docker build invocation failed");
    assert!(
        build.status.success(),
        "docker build failed for {dockerfile}:\n{}",
        String::from_utf8_lossy(&build.stderr)
    );

    // Run the inner suite: one container, NET_ADMIN, sequential tests.
    let mut args: Vec<String> = vec![
        "run".into(),
        "--rm".into(),
        "--cap-add=NET_ADMIN".into(),
        "-e".into(),
        "LHFM_ITEST_INNER=1".into(),
        "-e".into(),
        "RUST_BACKTRACE=1".into(),
        tag.into(),
        "lhfm-itest".into(),
        "--exact".into(),
    ];
    args.extend(tests.iter().map(|t| t.to_string()));
    args.extend(["--test-threads=1".to_string(), "--nocapture".to_string()]);
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let out = docker_with_timeout(900, &arg_refs, &repo_root, &format!("docker run ({tag})"))
        .expect("docker run invocation failed");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    print!("{stdout}");
    eprint!("{stderr}");
    assert!(
        out.status.success(),
        "inner suite failed in {tag} (exit {status:?}) — output above",
        status = out.status.code().unwrap_or(-1),
    );
}

/// Run a docker command under coreutils `timeout` so a wedged build/run can't
/// hang the suite forever.
fn docker_with_timeout(secs: u64, args: &[&str], cwd: &str, what: &str) -> std::io::Result<Output> {
    let started = Instant::now();
    let out = Command::new("timeout")
        .arg(secs.to_string())
        .arg("docker")
        .args(args)
        .current_dir(cwd)
        .output()?;
    eprintln!("[itest] {what} took {}s", started.elapsed().as_secs());
    Ok(out)
}

#[test]
fn container_suites_run() {
    if std::env::var("LHFM_CONTAINER_ITEST").as_deref() != Ok("1") {
        eprintln!(
            "skipping container backend suites: opt in with LHFM_CONTAINER_ITEST=1 (docker required) — see `just itest`"
        );
        return;
    }
    // Explicit opt-in but broken docker → fail loudly, never silently pass.
    let probe = Command::new("docker")
        .arg("info")
        .output()
        .expect("docker binary must exist when LHFM_CONTAINER_ITEST=1");
    assert!(
        probe.status.success(),
        "docker daemon not reachable:\n{}",
        String::from_utf8_lossy(&probe.stderr)
    );

    run_suite("Dockerfile.ufw", "lhfm-itest-ufw", UFW_SUITE);
    run_suite(
        "Dockerfile.firewalld",
        "lhfm-itest-firewalld",
        FIREWALLD_SUITE,
    );
}

// ── Shared inner helpers ─────────────────────────────────────────────────

/// Inner tests only do real work inside the container; on the host they are
/// no-ops (the outer harness runs them inside the image).
fn in_container() -> bool {
    std::env::var("LHFM_ITEST_INNER").as_deref() == Ok("1")
}

fn allow_rule(name: &str) -> FirewallRule {
    FirewallRule {
        id: uuid::Uuid::new_v4(),
        name: name.to_string(),
        description: String::new(),
        action: FirewallAction::Allow,
        direction: FirewallDirection::In,
        protocol: FirewallProtocol::Tcp,
        src_cidr: None,
        src_port_start: None,
        src_port_end: None,
        dst_cidr: None,
        dst_port_start: Some(22),
        dst_port_end: Some(22),
        interface_in: None,
        interface_out: None,
        comment: String::new(),
        log: false,
        priority: 0,
        created_by: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

fn ctx(def_in: Option<&str>, def_out: Option<&str>) -> ApplyContext {
    ApplyContext {
        manager_ip: "10.0.0.1".to_string(),
        manager_port: 8443,
        default_input_policy: def_in.map(String::from),
        default_output_policy: def_out.map(String::from),
    }
}

// ── UFW inner suite ──────────────────────────────────────────────────────

#[tokio::test]
async fn it_ufw_apply_deny_deny_umbilical_and_status() {
    if !in_container() {
        return;
    }
    let backend = UfwBackend;
    backend.reset().await.expect("ufw reset");

    let compiled = backend
        .compile(&[allow_rule("ssh")], &ctx(Some("deny"), Some("deny")))
        .await
        .expect("compile");
    // Umbilical + 2 defaults + 1 policy rule.
    assert_eq!(
        compiled.commands.len(),
        4,
        "compiled: {:?}",
        compiled.commands
    );

    let result = backend.apply(&compiled).await.expect("apply");
    assert!(result.error.is_none(), "apply errors: {:?}", result.error);
    assert_eq!(result.failed, 0);
    assert_eq!(result.applied, 4);

    // Default policies took effect (PR #10 live-verification gap).
    let status = backend.status().await.expect("status");
    assert!(status.active);
    assert_eq!(status.default_policy_in, "deny", "status: {status:?}");
    assert_eq!(status.default_policy_out, "deny", "status: {status:?}");

    // The umbilical allow-out to the manager survives in the live UFW state,
    // and the policy's ssh allow is present.
    let snap = backend.snapshot().await.expect("snapshot");
    assert!(
        snap.rules
            .iter()
            .any(|r| r.contains("8443") && r.contains("ALLOW OUT")),
        "umbilical rule must be in live ufw status: {:?}",
        snap.rules
    );
    assert!(
        snap.rules.iter().any(|r| r.contains("22/tcp")),
        "ssh allow must be in live ufw status: {:?}",
        snap.rules
    );
    assert!(!result.snapshot_hash.is_empty());
}

#[tokio::test]
async fn it_ufw_reapply_converges_same_snapshot_hash() {
    if !in_container() {
        return;
    }
    let backend = UfwBackend;
    backend.reset().await.expect("ufw reset");

    let compiled = backend
        .compile(&[allow_rule("ssh")], &ctx(Some("deny"), Some("deny")))
        .await
        .expect("compile");
    let first = backend.apply(&compiled).await.expect("first apply");
    assert!(
        first.error.is_none(),
        "first apply errors: {:?}",
        first.error
    );

    // A second identical apply must converge: same snapshot hash, no errors —
    // this is what lets the agent stop re-applying once in sync.
    let second = backend.apply(&compiled).await.expect("second apply");
    assert!(
        second.error.is_none(),
        "second apply errors: {:?}",
        second.error
    );
    assert_eq!(
        first.snapshot_hash, second.snapshot_hash,
        "converged applies must produce identical snapshots"
    );

    // Snapshotting alone is deterministic too.
    let again = backend.snapshot().await.expect("snapshot");
    assert_eq!(again.hash, second.snapshot_hash);
}

#[tokio::test]
async fn it_ufw_null_defaults_leave_previous_policies_sticky() {
    if !in_container() {
        return;
    }
    let backend = UfwBackend;
    backend.reset().await.expect("ufw reset");

    // deny/deny policy set first.
    let compiled = backend
        .compile(&[allow_rule("ssh")], &ctx(Some("deny"), Some("deny")))
        .await
        .expect("compile");
    let applied = backend.apply(&compiled).await.expect("deny/deny apply");
    assert!(applied.error.is_none(), "errors: {:?}", applied.error);
    assert_eq!(backend.status().await.unwrap().default_policy_out, "deny");

    // Policy set with null defaults = "leave the direction alone": no `ufw
    // default` command runs. Verified ufw behavior: the per-direction default
    // lives in /etc/default/ufw and `ufw --force reset` does NOT restore it to
    // installation defaults — so the previously applied deny/deny stays in
    // force. A policy set that wants allow-out must set it explicitly; the
    // umbilical keeps the manager reachable either way.
    let compiled = backend
        .compile(&[allow_rule("ssh")], &ctx(None, None))
        .await
        .expect("compile");
    assert!(
        !compiled
            .commands
            .iter()
            .any(|c| c.starts_with("ufw default")),
        "no ufw default commands when defaults are None: {:?}",
        compiled.commands
    );
    let applied = backend.apply(&compiled).await.expect("null-defaults apply");
    assert!(applied.error.is_none(), "errors: {:?}", applied.error);
    let status = backend.status().await.unwrap();
    assert_eq!(status.default_policy_in, "deny", "status: {status:?}");
    assert_eq!(status.default_policy_out, "deny", "status: {status:?}");
}

#[tokio::test]
async fn it_ufw_reset_deactivates() {
    if !in_container() {
        return;
    }
    let backend = UfwBackend;
    backend.reset().await.expect("ufw reset");
    assert!(
        !backend.status().await.unwrap().active,
        "after reset UFW must be inactive"
    );
}

// ── firewalld inner suite ────────────────────────────────────────────────

/// Start firewalld in the container (no systemd): the system dbus (classic
/// `dbus-daemon` — dbus-broker's launcher only inherits systemd-passed
/// sockets), then firewalld in the foreground as a detached child. Poll
/// `firewall-cmd --state` until it reports running.
fn ensure_firewalld() {
    let state = || -> bool {
        Command::new("firewall-cmd")
            .arg("--state")
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "running")
            .unwrap_or(false)
    };
    if state() {
        return;
    }
    let _ = Command::new("mkdir").args(["-p", "/run/dbus"]).status();
    // Ignore "already running" style failures; the poll below is the verdict.
    let _ = Command::new("dbus-daemon")
        .args(["--system", "--fork"])
        .status();
    let _ = Command::new("firewalld")
        .args(["--nofork", "--nopid"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
    let deadline = Instant::now() + Duration::from_secs(60);
    while Instant::now() < deadline {
        if state() {
            return;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    panic!("firewalld did not reach 'running' within 60s");
}

#[tokio::test]
async fn it_firewalld_apply_rich_rules_and_snapshot() {
    if !in_container() {
        return;
    }
    ensure_firewalld();

    let backend = FirewalldBackend;
    let mut ssh = allow_rule("ssh");
    ssh.src_cidr = Some("10.0.0.0/8".to_string());
    let compiled = backend
        .compile(&[ssh], &ctx(None, None))
        .await
        .expect("compile");
    assert_eq!(compiled.commands.len(), 1);

    let result = backend.apply(&compiled).await.expect("apply");
    assert!(result.error.is_none(), "apply errors: {:?}", result.error);
    assert_eq!(result.failed, 0);
    assert_eq!(result.applied, 1);

    let snap = backend.snapshot().await.expect("snapshot");
    assert!(
        snap.rules.iter().any(|r| r.contains("10.0.0.0/8")),
        "rich rule source must appear in firewall-cmd --list-all: {:?}",
        snap.rules
    );
    let again = backend.snapshot().await.expect("snapshot");
    assert_eq!(snap.hash, again.hash, "snapshot must be deterministic");
}

#[tokio::test]
async fn it_firewalld_reset_clears_rules() {
    if !in_container() {
        return;
    }
    ensure_firewalld();

    let backend = FirewalldBackend;
    let mut http = allow_rule("http");
    http.src_cidr = Some("192.168.0.0/16".to_string());
    http.dst_port_start = Some(80);
    http.dst_port_end = Some(80);
    let compiled = backend
        .compile(&[http], &ctx(None, None))
        .await
        .expect("compile");
    let applied = backend.apply(&compiled).await.expect("apply");
    assert!(applied.error.is_none(), "apply errors: {:?}", applied.error);
    assert!(
        backend
            .snapshot()
            .await
            .unwrap()
            .rules
            .iter()
            .any(|r| r.contains("192.168.0.0/16")),
        "rule must be present before reset"
    );

    backend.reset().await.expect("reset");
    assert!(
        !backend
            .snapshot()
            .await
            .unwrap()
            .rules
            .iter()
            .any(|r| r.contains("192.168.0.0/16")),
        "reset must remove applied rules"
    );
}
