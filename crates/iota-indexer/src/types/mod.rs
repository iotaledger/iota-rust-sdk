#[derive(Clone, Debug)]
pub struct TransactionRecord {
    pub digest: String,
    pub sender: String,
    pub kind: String,
    pub success: bool,
    pub tx_bcs_base64: String,
    pub effects_bcs_base64: String,
}

#[derive(Clone, Debug)]
pub struct EventRecord {
    pub tx_digest: String,
    pub event_index: i64,
    pub sender: Option<String>,
    pub emitting_module: Option<String>,
    pub package: Option<String>,
    pub event_type: String,
    pub event_timestamp: Option<String>,
    pub event_json: String,
    pub event_bcs_base64: String,
}
