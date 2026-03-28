use chrono::Utc;
use serde_json::{json, Value};
use tracing::{error, info, warn};

use super::mitre::Mitre;

pub fn init_logging() {
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .json()
        .flatten_event(true)
        .with_current_span(false)
        .with_span_list(false)
        .finish();

    tracing::subscriber::set_global_default(subscriber)
        .expect("Failed to set global subscriber");
}

pub fn log_event(
    level: &str,
    message: &str,
    service_name: &str,
    mitre: Option<Mitre>,
) {
    let timestamp = Utc::now().to_rfc3339();

    let mut log: Value = json!({
        "@timestamp": timestamp,
        "log.level": level,
        "message": message,
        "service.name": service_name,
        "event.dataset": "application",
        "event.module": "rust-app"
    });

    if let Some(m) = mitre {
        if let Some(tactic) = m.tactic_id {
            log["threat.tactic.id"] = json!(tactic);
        }
        if let Some(tech_id) = m.technique_id {
            log["threat.technique.id"] = json!(tech_id);
        }
        if let Some(name) = m.technique_name {
            log["threat.technique.name"] = json!(name);
        }
    }

    match level {
        "critical" => error!("{}", log),
        "warning" => warn!("{}", log),
        _ => info!("{}", log),
    }
}