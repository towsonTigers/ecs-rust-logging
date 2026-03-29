use std::collections::HashMap;

use crate::logging::mitre::Mitre;
use crate::logging::mitre::technique;

pub fn mitre_lookup_table() -> HashMap<&'static str, Mitre> {
    let mut map = HashMap::new();

    // 🔐 Authentication attacks
    map.insert(
        technique::BRUTE_FORCE,
        Mitre {
            tactic_id: Some("TA0006".into()),      // Credential Access
            technique_id: Some("T1110".into()),    // Brute Force
            technique_name: Some("Brute Force".into()),
        },
    );

    map.insert(
        "AUTH_CREDENTIAL_STUFFING",
        Mitre {
            tactic_id: Some("TA0006".into()),
            technique_id: Some("T1110.004".into()),
            technique_name: Some("Credential Stuffing".into()),
        },
    );

    // 🧑‍💻 Execution
    map.insert(
        "PROCESS_SUSPICIOUS_EXECUTION",
        Mitre {
            tactic_id: Some("TA0002".into()),      // Execution
            technique_id: Some("T1059".into()),    // Command and Scripting Interpreter
            technique_name: Some("Command Execution".into()),
        },
    );

    // 🌐 Lateral movement
    map.insert(
        "LATERAL_MOVEMENT_SMB",
        Mitre {
            tactic_id: Some("TA0008".into()),
            technique_id: Some("T1021.002".into()),
            technique_name: Some("SMB/Windows Admin Shares".into()),
        },
    );

    // 📦 Data exfiltration
    map.insert(
        "DATA_EXFILTRATION",
        Mitre {
            tactic_id: Some("TA0010".into()),
            technique_id: Some("T1041".into()),
            technique_name: Some("Exfiltration Over C2 Channel".into()),
        },
    );

    map
}