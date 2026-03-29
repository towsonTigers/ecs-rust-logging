mod logging;

use logging::ecs::{init_logging, log_event_with_lookup, log_warning, log_info};

use crate::logging::mitre::technique;

fn main() {
    init_logging();

    // Automatically mapped to MITRE
    log_event_with_lookup(
        technique::BRUTE_FORCE,
        "Multiple failed login attempts detected",
        "auth-service",
    );

    // Another mapped event
    log_event_with_lookup(
        "PROCESS_SUSPICIOUS_EXECUTION",
        "Suspicious PowerShell execution detected",
        "endpoint-agent",
    );

    // Unknown event (no MITRE mapping)
    log_event_with_lookup(
        "USER_LOGIN",
        "User logged in successfully",
        "auth-service",
    );

    log_warning(
       "foobar encountered",
       "foo service"
    );

    log_info(
        "look here",
        "service"
    );
}