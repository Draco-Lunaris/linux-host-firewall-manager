use fw_core::models::FirewallRule;

pub fn compile_rule(_rule: &FirewallRule, _backend: &str) -> Vec<String> {
    Vec::new()
}
