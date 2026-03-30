mod logging;

use logging::ecs::{init_logging, log_error, log_warning, log_info, log_debug, log_trace};

use crate::logging::mitre::technique;

fn main() {

    init_logging();

    // Automatically mapped to MITRE
    log_error(
        technique::BRUTE_FORCE,
        "Multiple failed login attempts detected",
        "auth-service",
    );

    // Another mapped event
    log_error(
        "PROCESS_SUSPICIOUS_EXECUTION",
        "Suspicious PowerShell execution detected",
        "endpoint-agent",
    );

    // Unknown event (no MITRE mapping)
    log_debug("USER_LOGIN","User logged in successfully","auth-service");

   log_warning("foo","foobar encountered","foo service");

    log_info("bar","look here","service");

    log_trace("bar","look here","service");
}