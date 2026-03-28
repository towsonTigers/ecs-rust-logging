use serde::Serialize;

#[derive(Serialize, Debug, Clone)]
pub struct Mitre {
    #[serde(rename = "threat.tactic.id")]
    pub tactic_id: Option<String>,

    #[serde(rename = "threat.technique.id")]
    pub technique_id: Option<String>,

    #[serde(rename = "threat.technique.name")]
    pub technique_name: Option<String>,
}