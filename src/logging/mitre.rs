use serde::Serialize;

#[allow(unused)]
pub mod tactic {
    pub const INITIAL_ACCESS: &str = "TA0001";
    pub const EXECUTION: &str = "TA0002";
    pub const PERSISTENCE: &str = "TA0003";
    pub const PRIVILEGE_ESCALATION: &str = "TA0004";
    pub const DEFENSE_EVASION: &str = "TA0005";
    pub const CREDENTIAL_ACCESS: &str = "TA0006";
    pub const DISCOVERY: &str = "TA0007";
    pub const LATERAL_MOVEMENT: &str = "TA0008";
    pub const COLLECTION: &str = "TA0009";
    pub const EXFILTRATION: &str = "TA0010";
    pub const COMMAND_AND_CONTROL: &str = "TA0011";
    pub const IMPACT: &str = "TA0040";
}

#[allow(unused)]
pub mod technique {
    pub const BRUTE_FORCE: &str = "T1110";
    pub const PHISHING: &str = "T1566";
    pub const POWER_SHELL: &str = "T1059.001";
    pub const CREDENTIAL_DUMPING: &str = "T1003";
}

#[derive(Serialize, Debug, Clone)]
pub struct Mitre {
    #[serde(rename = "threat.tactic.id")]
    pub tactic_id: Option<String>,

    #[serde(rename = "threat.technique.id")]
    pub technique_id: Option<String>,

    #[serde(rename = "threat.technique.name")]
    pub technique_name: Option<String>,
}