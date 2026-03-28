//use chrono::Utc;
//use tracing::{error, warn, info}; //debug??

use serde_json::{json, Value};

use super::mitre::Mitre;
use super::mitre_lookup::mitre_lookup_table;

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
    let ecs_log = to_ecs(
        level,
        message,
        service_name,
        "application",
        "rust-app",
        mitre,
    );
    // NDJSON output (single line, no pretty print)
    println!("{}", serde_json::to_string(&ecs_log).unwrap());
}

/* pub fn log_event(
    level: &str,
    message: &str,
    service_name: &str,
    mitre: Option<Mitre>,
) {
    let timestamp = Utc::now().to_rfc3339();

    match (level, mitre) {
        ("critical", Some(m)) => {
            error!(
             //   %timestamp,
             //   log_level = level,
                message = message,
                service_name = service_name,
                event_dataset = "application",
                event_module = "rust-app",
                threat_tactic_id = m.tactic_id.unwrap_or_default(),
                threat_technique_id = m.technique_id.unwrap_or_default(),
                threat_technique_name = m.technique_name.unwrap_or_default()
            );
        }
        ("critical", None) => {
            error!(
              //  %timestamp,
              //  log_level = level,
                message = message,
                service_name = service_name,
                event_dataset = "application",
                event_module = "rust-app"
            );
        }
        ("warning", _) => {
            warn!(
            //    %timestamp,
            //    log_level = level,
                message = message,
                service_name = service_name,
                event_dataset = "application",
                event_module = "rust-app"
            );
        }
        _ => {
            info!(
            //    %timestamp,
            //    log_level = level,
                message = message,
                service_name = service_name,
                event_dataset = "application",
                event_module = "rust-app"
            );
        }
    }
} */

pub fn log_event_with_lookup(
    event_key: &str,
    message: &str,
    service_name: &str,
) {
    let lookup = mitre_lookup_table();

    let mitre = lookup.get(event_key);

    let level = if mitre.is_some() {
        "critical" // security events default to critical
    } else {
        "info"
    };

    super::ecs::log_event(
        level,
        message,
        service_name,
        mitre.cloned(),
    );
}

fn to_ecs(
    level: &str,
    message: &str,
    service_name: &str,
    event_dataset: &str,
    event_module: &str,
    mitre: Option<crate::logging::mitre::Mitre>,
) -> Value {
    json!({
        "@timestamp": chrono::Utc::now().to_rfc3339(),
        "log.level": level,
        "message": message,
        "service.name": service_name,
        "event.dataset": event_dataset,
        "event.module": event_module,
        "threat.tactic.id": mitre.as_ref().and_then(|m| m.tactic_id.clone()),
        "threat.technique.id": mitre.as_ref().and_then(|m| m.technique_id.clone()),
        "threat.technique.name": mitre.as_ref().and_then(|m| m.technique_name.clone())
    })
}