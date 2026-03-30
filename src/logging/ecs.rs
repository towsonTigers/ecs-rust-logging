use serde_json::{json, Value};

use super::mitre::Mitre;
use super::mitre_lookup::mitre_lookup_table;

/* Standard ECS log levels

    ECS doesn’t strictly enforce a fixed list, but it recommends the common industry levels:

    Most commonly used

   0 trace – very detailed, low-level debugging
   1 debug – useful for developers
   2 info – normal operational messages
   3 warn (or warning) – something unexpected but not fatal
   4 error – failure in part of the system
   5 fatal (or critical) – severe failure, system may stop
 */
const LOG_LEVEL: [&str; 6] = ["TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL"];

pub fn init_logging() {

    let subscriber = tracing_subscriber::fmt()
        .json()
        .flatten_event(true)
        .with_current_span(false)
        .with_span_list(false)
        .finish();

    tracing::subscriber::set_global_default(subscriber)
        .expect("Failed to set global subscriber");
}

#[allow(unused)]
pub fn log_trace(
    message: &str,
    service_name: &str,
    event_key: &str
) {
    log(0, message, service_name, event_key);
}

#[allow(unused)]
pub fn log_debug(
    message: &str,
    service_name: &str,
    event_key: &str
) {
    log(1, message, service_name, event_key);
}

#[allow(unused)]
pub fn log_info(
    message: &str,
    service_name: &str,
    event_key: &str
) {
    log(2, message, service_name, event_key);
}

#[allow(unused)]
pub fn log_warning(
    message: &str,
    service_name: &str,
    event_key: &str
) {
    log(3, message, service_name, event_key);
}

#[allow(unused)]
pub fn log_error(
    message: &str,
    service_name: &str,
    event_key: &str
) {
    log(4, message, service_name, event_key);
}

#[allow(unused)]
pub fn log_fatal(
    message: &str,
    service_name: &str,
    event_key: &str
) {
    log(5, message, service_name, event_key);
}

fn log(
    level: usize,
    message: &str,
    service_name: &str,
    event_key: &str
) {

    //LOG LEVEL CHECK
    // if level<RUST_LOG return;
    // levelMsg
    if event_key.trim().is_empty() {
         log_event(LOG_LEVEL[level], message, service_name, None);
    } else {
         log_event_with_lookup(LOG_LEVEL[level], message, service_name, event_key);
    }
}

fn log_event(
    level_name: &str,
    message: &str,
    service_name: &str,
    mitre: Option<Mitre>
) {
    let ecs_log = to_ecs(
        level_name,
        message,
        service_name,
        "application",
        "rust-app",
        mitre,
    );
    // NDJSON output (single line, no pretty print)
    println!("{}", serde_json::to_string(&ecs_log).unwrap());
}

fn log_event_with_lookup(
    level_name:  &str,
    message: &str,
    service_name: &str,    
    event_key: &str,
) {
    let lookup = mitre_lookup_table();
    let mitre = lookup.get(event_key);

    super::ecs::log_event(
        level_name,
        message,
        service_name,
        mitre.cloned(),
    );
}

fn to_ecs(
    level_name: &str,
    message: &str,
    service_name: &str,
    event_dataset: &str,
    event_module: &str,
    mitre: Option<crate::logging::mitre::Mitre>,
) -> Value {
    json!({
        "@timestamp": chrono::Utc::now().to_rfc3339(),
        "log.level": level_name,
        "message": message,
        "service.name": service_name,
        "event.dataset": event_dataset,
        "event.module": event_module,
        "threat.tactic.id": mitre.as_ref().and_then(|m| m.tactic_id.clone()),
        "threat.technique.id": mitre.as_ref().and_then(|m| m.technique_id.clone()),
        "threat.technique.name": mitre.as_ref().and_then(|m| m.technique_name.clone())
    })
}