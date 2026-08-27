//! Pull loop — the main periodic check-in cycle for the agent.
//!
//! Runs as a background tokio task. On each cycle:
//! 1. Compute current rules hash from the backend snapshot
//! 2. Call the manager's check-in endpoint
//! 3. If rules changed, compile and apply the new rules
//! 4. Execute any pending actions
//! 5. Apply config updates
//! 6. Report results back to the manager
//! 7. Sleep for the configured interval, then repeat

use anyhow::{Context, Result};
use fw_core::models::{FirewallAction, FirewallDirection, FirewallProtocol, FirewallRule};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

use crate::backend::FirewallBackend;
use crate::config::AgentConfig;
use crate::pull_client::{CheckInRequest, CheckInResultRequest, PullClient, RuleDto};

/// Acquire an exclusive flock on `/run/firewall-agent/apply.lock` so that two
/// agent processes — or a pending-action apply racing a rules-changed apply —
/// can't compile+apply at the same time. The lock is held for as long as the
/// returned `File` lives (released on drop). Acquired on a blocking thread so
/// the wait doesn't stall the async runtime.
fn acquire_apply_lock() -> std::io::Result<std::fs::File> {
    use std::os::unix::io::AsRawFd;
    const PATH: &str = "/run/firewall-agent/apply.lock";
    if let Some(parent) = std::path::Path::new(PATH).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let file = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(true)
        .open(PATH)?;
    let r = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
    if r == 0 {
        Ok(file)
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// SHA-256 of the running agent binary (current_exe), computed once per process
/// and sent on each check-in for integrity tracking (SEC-007 stub). Returns
/// None if the binary can't be read.
fn agent_binary_hash() -> Option<String> {
    static HASH: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
    HASH.get_or_init(|| {
        let exe = std::env::current_exe().ok()?;
        let bytes = std::fs::read(&exe).ok()?;
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        Some(hex::encode(hasher.finalize()))
    })
    .clone()
}

/// Parse the agent's `manager_agent_url` into a (ip, port) pair for the apply
/// context. The URL is normalized to an IP at enrollment, so this only verifies
/// it's still a specific IP and extracts the port. Returns an error if the URL
/// is malformed, has no host/port, or the host isn't a specific IP — the caller
/// (safety gate) refuses to apply in that case rather than risk a lockout.
fn manager_endpoint(manager_url: &str) -> Result<(String, u16)> {
    let parsed = url::Url::parse(manager_url)
        .map_err(|e| anyhow::anyhow!("invalid manager_agent_url: {e}"))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("manager_agent_url has no host"))?;
    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| anyhow::anyhow!("manager_agent_url has no port"))?;
    let ip: std::net::IpAddr = host
        .parse()
        .map_err(|_| anyhow::anyhow!("manager_agent_url host is not an IP (got {host}); re-enroll with an IP manager address"))?;
    if ip.is_unspecified() {
        anyhow::bail!(
            "manager_agent_url is an unspecified address ({ip}); re-enroll with a specific IP"
        );
    }
    Ok((ip.to_string(), port))
}

/// Run the pull loop as a background task.
pub async fn run_pull_loop(
    backend: Arc<dyn FirewallBackend>,
    config: Arc<RwLock<AgentConfig>>,
    pull_client: PullClient,
) {
    let host_id = config
        .read()
        .await
        .host_id
        .as_ref()
        .and_then(|s| uuid::Uuid::parse_str(s).ok())
        .unwrap_or_default();
    let mut interval_secs = config.read().await.pull.check_in_interval_secs;
    let mut config_version = config.read().await.pull.config_version;
    let safe_mode =
        crate::safe_mode::SafeModeState::new(config.read().await.safe_mode_timeout_secs);

    loop {
        tracing::info!(host_id = %host_id, interval = interval_secs, "Pull cycle starting");

        let local_drift = match run_pull_cycle(
            &backend,
            &config,
            &pull_client,
            &safe_mode,
            host_id,
            &mut interval_secs,
            &mut config_version,
        )
        .await
        {
            Ok(d) => d,
            Err(e) => {
                tracing::error!(error = %e, "Pull cycle failed");
                false
            }
        };

        // On local drift, check in again soon (30s) instead of waiting the full
        // interval, so the manager can re-apply the expected ruleset.
        let wait_secs = if local_drift { 30 } else { interval_secs };
        wait_for_next_cycle(&pull_client, wait_secs).await;
    }
}

/// Wait for the next pull cycle. Prefers the manager's SSE events stream
/// (Stream 5): an operator "force check-in" emits a `check-in` event that
/// wakes us immediately, and the stream's hold-window timeout (or any drop)
/// also wakes us so the next cycle runs on schedule. If the SSE stream is
/// unavailable, the `sleep(interval)` branch bounds the wait. The manager
/// never opens a connection to the agent — the agent holds this subscription.
async fn wait_for_next_cycle(pull_client: &PullClient, interval_secs: u32) {
    let notify = std::sync::Arc::new(tokio::sync::Notify::new());
    let sse_notify = notify.clone();
    let pc = pull_client.clone();
    let sse_task = tokio::spawn(async move {
        if let Err(e) = pc.run_events_stream(sse_notify).await {
            tracing::warn!(error = %e, "SSE events stream ended; will sleep instead");
        }
    });

    tokio::select! {
        _ = notify.notified() => {}
        _ = tokio::time::sleep(Duration::from_secs(interval_secs.max(60) as u64)) => {}
    }
    sse_task.abort();
}

async fn run_pull_cycle(
    backend: &Arc<dyn FirewallBackend>,
    config: &Arc<RwLock<AgentConfig>>,
    pull_client: &PullClient,
    safe_mode: &crate::safe_mode::SafeModeState,
    host_id: uuid::Uuid,
    interval_secs: &mut u32,
    config_version: &mut i32,
) -> Result<bool> {
    // 1. Snapshot the live firewall rules. The live hash is used only for
    //    local drift detection (out-of-band changes vs the last-applied
    //    snapshot below). The hash we *report* to the manager is the
    //    field-hash of the rules we last applied (see below), so the
    //    manager's comparison is apples-to-apples and a converged host stops
    //    re-applying every cycle.
    let snapshot = backend
        .snapshot()
        .await
        .context("Failed to get backend snapshot")?;
    let live_hash = snapshot.hash;

    // Reported rules_hash = the field-hash of the rules we last applied
    // (cached as last_good). Empty when we've never applied (the manager
    // sends the policy on the first check-in). Recomputed from last_good
    // each cycle so a daemon restart with an intact cache reports the
    // matching hash and doesn't trigger a needless re-apply.
    let reported_rules_hash = crate::safe_mode::load_last_good()
        .map(|applied| {
            let parts: Vec<fw_core::models::RuleHashParts<'_>> = applied
                .iter()
                .map(|r| fw_core::models::RuleHashParts {
                    id: &r.id,
                    action: r.action.as_str(),
                    direction: r.direction.as_str(),
                    protocol: r.protocol.as_str(),
                    src_cidr: r.src_cidr.as_deref(),
                    dst_cidr: r.dst_cidr.as_deref(),
                    dst_port_start: r.dst_port_start,
                })
                .collect();
            fw_core::models::compute_rules_hash(&parts)
        })
        .unwrap_or_default();

    // Local drift: the live rules differ from the last-applied ruleset (someone
    // changed them out-of-band). Schedule an early check-in so the manager can
    // re-apply sooner. (The manager also detects this via check_in_mismatch.)
    let local_drift = match crate::drift::load_expected_hash() {
        Some(expected) if expected != live_hash => {
            tracing::warn!(
                expected = %expected,
                actual = %live_hash,
                "Local drift detected — live rules differ from last applied; scheduling early check-in"
            );
            true
        }
        _ => false,
    };

    // 2. Gather agent info
    let _backend_status = backend
        .status()
        .await
        .context("Failed to get backend status")?;
    let os_info = gather_os_info();
    let uptime = get_uptime_seconds();

    // 3. Call check-in
    let req = CheckInRequest {
        host_id,
        rules_hash: reported_rules_hash.clone(),
        agent_version: env!("CARGO_PKG_VERSION").to_string(),
        backend_type: backend.name().to_string(),
        os_info,
        uptime_seconds: uptime,
        config_version: *config_version,
        local_drift,
        agent_binary_hash: agent_binary_hash(),
    };

    let safe_mode_enabled = config.read().await.safe_mode_enabled;

    // 3. Call check-in. On success, record manager contact for safe mode. On
    // failure, if safe mode is enabled and the unreachable timeout has elapsed,
    // revert to the last-known-good ruleset rather than leaving the host running
    // a stale/unmanaged ruleset.
    let response = match pull_client.check_in(&req).await {
        Ok(r) => {
            safe_mode.record_manager_contact();
            r
        }
        Err(e) => {
            if safe_mode_enabled && safe_mode.check() {
                tracing::warn!(error = %e, "Manager unreachable; safe mode active — reverting to last-known-good");
                if let Ok(last_good) = crate::safe_mode::load_last_good() {
                    if !last_good.is_empty() {
                        let protected_cidrs = config.read().await.protected_cidrs.clone();
                        let cached_defaults =
                            crate::safe_mode::load_last_defaults().unwrap_or_default();
                        let (manager_ip, manager_port) = {
                            let url = config.read().await.pull.manager_agent_url.clone();
                            match manager_endpoint(&url) {
                                Ok(ep) => ep,
                                Err(ep_err) => {
                                    tracing::error!(error = %ep_err, "safe-mode revert: cannot build umbilical; keeping current rules");
                                    return Ok(false);
                                }
                            }
                        };
                        let ctx = crate::backend::ApplyContext {
                            manager_ip,
                            manager_port,
                            default_input_policy: cached_defaults.default_input_policy.clone(),
                            default_output_policy: cached_defaults.default_output_policy.clone(),
                        };
                        if let Err(revert_err) =
                            apply_rules(backend, &last_good, &protected_cidrs, &ctx).await
                        {
                            tracing::error!(error = %revert_err, "Safe-mode revert apply failed");
                        }
                    }
                }
            } else {
                tracing::warn!(error = %e, "Check-in failed");
            }
            return Ok(false);
        }
    };

    // 4. Apply config updates if present
    if let Some(ref cfg_update) = response.config {
        *interval_secs = cfg_update.check_in_interval_secs as u32;
        *config_version = cfg_update.config_version;

        {
            let mut cfg = config.write().await;
            cfg.pull.check_in_interval_secs = *interval_secs;
            cfg.pull.config_version = *config_version;
            cfg.safe_mode_enabled = cfg_update.safe_mode_enabled;
        }
        tracing::info!(
            interval = *interval_secs,
            version = *config_version,
            "Config updated from manager"
        );
        // Persist to disk so a daemon restart starts from the latest config
        // rather than the stale enrollment value (which would re-fetch on the
        // first check-in — harmless, but the on-disk config should reflect
        // what the agent is actually running).
        if let Err(e) = config.read().await.save() {
            tracing::warn!(error = %e, "Failed to persist config update to disk");
        }
    }

    // 5. Apply rules. Three triggers, each leading to a single apply:
    //   - rules_changed: the manager's policy changed since we last applied
    //     → apply the new ruleset the manager just sent.
    //   - defaults_changed: the policy set's default input/output policy changed
    //     since we last applied → re-apply the ruleset with the new defaults.
    //   - local_drift: our live rules differ from what we last applied (an
    //     out-of-band change) → re-apply our cached last-applied ruleset
    //     (self-heal) with the cached defaults.
    // In steady state (none) we do nothing — no `ufw reset`, so no repeated
    // network interruption when nothing has changed.
    let cached_defaults = crate::safe_mode::load_last_defaults().unwrap_or_default();
    let defaults_changed = cached_defaults.default_input_policy != response.default_input_policy
        || cached_defaults.default_output_policy != response.default_output_policy;

    let (manager_ip, manager_port) = {
        let url = config.read().await.pull.manager_agent_url.clone();
        match manager_endpoint(&url) {
            Ok(ep) => ep,
            Err(e) => {
                tracing::error!(
                    error = %e,
                    "cannot build manager umbilical for apply; skipping apply this cycle"
                );
                (String::new(), 0u16) // safety gate inside apply_rules will bail
            }
        }
    };

    let protected_cidrs = config.read().await.protected_cidrs.clone();

    // The defaults that will be in effect after this apply (saved as
    // last_defaults on success so a defaults-only change stops re-triggering).
    let mut applied_defaults = cached_defaults.clone();
    let apply_outcome: Option<Result<String>> =
        if !response.rules.is_empty() && (response.rules_changed || defaults_changed) {
            if response.rules_changed {
                tracing::info!(
                    rule_count = response.rules.len(),
                    "Rules changed, applying new ruleset"
                );
            } else {
                tracing::info!("Default policy changed, re-applying ruleset with new defaults");
            }
            let ctx = crate::backend::ApplyContext {
                manager_ip: manager_ip.clone(),
                manager_port,
                default_input_policy: response.default_input_policy.clone(),
                default_output_policy: response.default_output_policy.clone(),
            };
            applied_defaults = crate::safe_mode::LastDefaults {
                default_input_policy: response.default_input_policy.clone(),
                default_output_policy: response.default_output_policy.clone(),
            };
            Some(apply_rules_from_dto(backend, &response.rules, &protected_cidrs, &ctx).await)
        } else if local_drift {
            tracing::info!("Local drift detected — re-applying last-applied ruleset (self-heal)");
            match crate::safe_mode::load_last_good() {
                Ok(last_good) if !last_good.is_empty() => {
                    let ctx = crate::backend::ApplyContext {
                        manager_ip: manager_ip.clone(),
                        manager_port,
                        default_input_policy: cached_defaults.default_input_policy.clone(),
                        default_output_policy: cached_defaults.default_output_policy.clone(),
                    };
                    Some(apply_rules(backend, &last_good, &protected_cidrs, &ctx).await)
                }
                _ => {
                    tracing::warn!("Local drift but no last-applied ruleset cached to re-apply");
                    None
                }
            }
        } else {
            None
        };

    if let Some(result) = apply_outcome {
        match result {
            Ok(new_hash) => {
                // Persist the last-applied hash for local drift detection.
                let _ = crate::drift::save_expected_hash(&new_hash);
                // Persist the defaults we just applied so a defaults-only change
                // stops re-triggering on the next cycle.
                let _ = crate::safe_mode::save_last_defaults(&applied_defaults);
                let result_req = CheckInResultRequest {
                    host_id,
                    action_id: None,
                    success: true,
                    error_message: None,
                    new_rules_hash: new_hash,
                };
                if let Err(e) = pull_client.report_result(&result_req).await {
                    tracing::warn!(error = %e, "Failed to report success to manager");
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "Failed to apply rules");
                let result_req = CheckInResultRequest {
                    host_id,
                    action_id: None,
                    success: false,
                    error_message: Some(e.to_string()),
                    new_rules_hash: live_hash.clone(),
                };
                if let Err(e) = pull_client.report_result(&result_req).await {
                    tracing::warn!(error = %e, "Failed to report error to manager");
                }
            }
        }
    }

    // 6. Execute pending actions (skip replays — already-executed actions whose
    // result report was likely lost; ack them without re-executing).
    for action in &response.pending_actions {
        if crate::replay_cache::already_executed(&action.id.to_string()) {
            tracing::info!(action_id = %action.id, "Pending action already executed — skipping replay");
            let result_req = CheckInResultRequest {
                host_id,
                action_id: Some(action.id),
                success: true,
                error_message: None,
                new_rules_hash: live_hash.clone(),
            };
            if let Err(e) = pull_client.report_result(&result_req).await {
                tracing::warn!(error = %e, "Failed to ack replayed action to manager");
            }
            continue;
        }
        tracing::info!(
            action_id = %action.id,
            action_type = %action.action_type,
            "Executing pending action"
        );
        let (success, error_msg) = execute_pending_action(backend, action).await;
        if success {
            let _ = crate::replay_cache::record(&action.id.to_string());
        }

        let result_req = CheckInResultRequest {
            host_id,
            action_id: Some(action.id),
            success,
            error_message: error_msg,
            new_rules_hash: live_hash.clone(),
        };
        if let Err(e) = pull_client.report_result(&result_req).await {
            tracing::warn!(error = %e, "Failed to report action result to manager");
        }
    }

    Ok(local_drift)
}

/// Convert RuleDto list to FirewallRule list, compile, and apply via backend.
/// Rules are first checked against the host's protected CIDRs (SEC-006): a
/// rule that would block a protected CIDR, or expose one to a broad source, is
/// rejected before it reaches the backend.
async fn apply_rules_from_dto(
    backend: &Arc<dyn FirewallBackend>,
    dtos: &[RuleDto],
    protected_cidrs: &[String],
    ctx: &crate::backend::ApplyContext,
) -> Result<String> {
    let rules: Vec<FirewallRule> = dtos.iter().map(dto_to_rule).collect();
    apply_rules(backend, &rules, protected_cidrs, ctx).await
}

/// Compile and apply a ruleset under the per-host apply mutex, after enforcing
/// protected CIDRs. Returns the new snapshot hash. Shared by the normal apply
/// path and the safe-mode revert (which already has FirewallRules, not DTOs).
async fn apply_rules(
    backend: &Arc<dyn FirewallBackend>,
    rules: &[FirewallRule],
    protected_cidrs: &[String],
    ctx: &crate::backend::ApplyContext,
) -> Result<String> {
    // Enforce protected CIDRs before compiling/applying.
    if let Err(violations) =
        crate::protected_cidrs::check_rules_against_protected(rules, protected_cidrs)
    {
        anyhow::bail!("protected CIDR violations: {}", violations.join("; "));
    }

    // Safety gate: never apply (and especially never `ufw reset` toward a
    // default-deny policy) unless the umbilical can be established — i.e. the
    // manager IP/port in ctx is a real, specific IP. Without it the agent could
    // lock itself out of the manager with no recovery. Bail here keeps the
    // last ruleset in place.
    if ctx.manager_ip.parse::<std::net::IpAddr>().is_err()
        || ctx
            .manager_ip
            .parse::<std::net::IpAddr>()
            .map(|ip| ip.is_unspecified())
            .unwrap_or(true)
    {
        anyhow::bail!(
            "cannot establish manager umbilical: manager_ip is not a specific IP (got \"{}\") — refusing to apply; re-enroll with an IP manager address",
            ctx.manager_ip
        );
    }

    // Hold the per-host apply mutex for the whole compile+apply so concurrent
    // applies can't race (S6.1). Acquired on a blocking thread; held until the
    // guard drops at the end of this function.
    let _apply_lock = tokio::task::spawn_blocking(acquire_apply_lock)
        .await
        .map_err(|e| anyhow::anyhow!("apply lock task: {}", e))?
        .map_err(|e| anyhow::anyhow!("acquire apply lock: {}", e))?;

    let compiled = backend
        .compile(rules, ctx)
        .await
        .map_err(|e| anyhow::anyhow!("Compile failed: {}", e))?;

    let result = backend
        .apply(&compiled)
        .await
        .map_err(|e| anyhow::anyhow!("Apply failed: {}", e))?;

    tracing::info!(
        applied = result.applied,
        failed = result.failed,
        "backend apply result"
    );
    if let Some(err) = &result.error {
        tracing::warn!(error = %err, "backend reported an apply error");
    }

    if result.failed > 0 {
        anyhow::bail!("{} rules failed to apply", result.failed);
    }

    // Persist this ruleset as the last-known-good for safe-mode revert (S6.2).
    let _ = crate::safe_mode::save_last_good(rules);

    Ok(result.snapshot_hash)
}

/// Convert a RuleDto (from manager API) to a FirewallRule (domain model).
fn dto_to_rule(dto: &RuleDto) -> FirewallRule {
    FirewallRule {
        id: dto.id,
        name: dto.name.clone(),
        description: String::new(),
        action: match dto.action.as_str() {
            "allow" => FirewallAction::Allow,
            "deny" => FirewallAction::Deny,
            "reject" => FirewallAction::Reject,
            "limit" => FirewallAction::Limit,
            "masquerade" => FirewallAction::Masquerade,
            _ => FirewallAction::Allow,
        },
        direction: match dto.direction.as_str() {
            "in" => FirewallDirection::In,
            "out" => FirewallDirection::Out,
            "forward" => FirewallDirection::Forward,
            _ => FirewallDirection::In,
        },
        protocol: match dto.protocol.as_str() {
            "any" => FirewallProtocol::Any,
            "tcp" => FirewallProtocol::Tcp,
            "udp" => FirewallProtocol::Udp,
            "icmp" => FirewallProtocol::Icmp,
            "icmpv6" => FirewallProtocol::Icmpv6,
            "gre" => FirewallProtocol::Gre,
            "esp" => FirewallProtocol::Esp,
            "ah" => FirewallProtocol::Ah,
            "sctp" => FirewallProtocol::Sctp,
            _ => FirewallProtocol::Any,
        },
        src_cidr: dto.src_cidr.clone(),
        src_port_start: dto.src_port_start,
        src_port_end: dto.src_port_end,
        dst_cidr: dto.dst_cidr.clone(),
        dst_port_start: dto.dst_port_start,
        dst_port_end: dto.dst_port_end,
        interface_in: dto.interface_in.clone(),
        interface_out: dto.interface_out.clone(),
        comment: dto.name.clone(),
        log: dto.log,
        priority: dto.priority,
        created_by: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

/// Execute a pending action received from the manager.
async fn execute_pending_action(
    backend: &Arc<dyn FirewallBackend>,
    action: &crate::pull_client::PendingActionDto,
) -> (bool, Option<String>) {
    match action.action_type.as_str() {
        "rollback" => match backend.reset().await {
            Ok(()) => (true, None),
            Err(e) => (false, Some(e.to_string())),
        },
        "safe_mode_on" => {
            tracing::warn!("safe_mode_on action not yet implemented");
            (true, None)
        }
        "safe_mode_off" => {
            tracing::warn!("safe_mode_off action not yet implemented");
            (true, None)
        }
        "reload_config" => (true, None),
        "agent_upgrade" => {
            tracing::warn!("agent_upgrade action not yet implemented");
            (true, None)
        }
        "apply_rules" => {
            // Rules will be applied on next check-in cycle if hash differs
            tracing::info!("apply_rules action — will be applied on next check-in");
            (true, None)
        }
        _ => (
            false,
            Some(format!("Unknown action type: {}", action.action_type)),
        ),
    }
}

fn gather_os_info() -> serde_json::Value {
    let container_runtime = crate::backend::container_detect::detect_container_runtime();
    let mut info = serde_json::json!({
        "hostname": hostname(),
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
    });
    if let Some(runtime) = container_runtime {
        info["container_runtime"] = serde_json::Value::String(runtime);
    }
    info
}

fn hostname() -> String {
    std::process::Command::new("hostname")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

fn get_uptime_seconds() -> i64 {
    std::fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|s| s.split_whitespace().next().map(|s| s.to_string()))
        .and_then(|s| s.parse::<f64>().ok())
        .map(|f| f as i64)
        .unwrap_or(0)
}
