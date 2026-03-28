mod logging;

use logging::ecs::{init_logging, log_event};
use logging::mitre::Mitre;

fn main() {
    init_logging();

    // Normal log
    log_event(
        "info",
        "User login successful",
        "auth-service",
        None,
    );

    // Warning log
    log_event(
        "warning",
        "User attempted invalid password",
        "auth-service",
        None,
    );

    // Security event with MITRE ATT&CK mapping
    log_event(
        "critical",
        "Multiple failed login attempts detected",
        "auth-service",
        Some(Mitre {
            tactic_id: Some("TA0006".into()),
            technique_id: Some("T1110".into()),
            technique_name: Some("Brute Force".into()),
        }),
    );
}