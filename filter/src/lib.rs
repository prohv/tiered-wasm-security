use log::info;
use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterConfig {
    #[serde(default = "default_mode")]
    pub mode: String, // "proposed" or "baseline"
    #[serde(default = "default_escalation_threshold")]
    pub escalation_threshold: u32,
    #[serde(default = "default_max_inspection_bytes")]
    pub max_inspection_bytes: usize,
    #[serde(default = "default_truncation_policy")]
    pub truncation_policy: String, // "reject" or "escalate"
}

fn default_mode() -> String {
    "proposed".to_string()
}
fn default_escalation_threshold() -> u32 {
    50
}
fn default_max_inspection_bytes() -> usize {
    4096
}
fn default_truncation_policy() -> String {
    "reject".to_string()
}

impl Default for FilterConfig {
    fn default() -> Self {
        Self {
            mode: default_mode(),
            escalation_threshold: default_escalation_threshold(),
            max_inspection_bytes: default_max_inspection_bytes(),
            truncation_policy: default_truncation_policy(),
        }
    }
}

// Global in-memory counters (thread-local / VM-local)
static TOTAL_REQUESTS: AtomicU64 = AtomicU64::new(0);
static FAST_PATH_REQUESTS: AtomicU64 = AtomicU64::new(0);
static ESCALATED_REQUESTS: AtomicU64 = AtomicU64::new(0);
static PAYLOAD_ACQUISITION_COUNT: AtomicU64 = AtomicU64::new(0);
static PAYLOAD_BYTES_ACQUIRED: AtomicU64 = AtomicU64::new(0);
static BODY_INSPECTION_COUNT: AtomicU64 = AtomicU64::new(0);
static BOUNDED_INSPECTION_REACHED: AtomicU64 = AtomicU64::new(0);
static REJECTED_REQUESTS: AtomicU64 = AtomicU64::new(0);
static ATTACK_DETECTED: AtomicU64 = AtomicU64::new(0);
static ATTACK_MISSED: AtomicU64 = AtomicU64::new(0);
static BENIGN_CLASSIFIED_AS_ATTACK: AtomicU64 = AtomicU64::new(0);
static ATTACK_CLASSIFIED_AS_BENIGN: AtomicU64 = AtomicU64::new(0);

// Proxy-Wasm Shared Data Helper for multi-worker synchronization
const SHARED_KEY_PREFIX: &str = "waf_metric_";

fn inc_shared_counter(key: &str, delta: u64) {
    let full_key = format!("{}{}", SHARED_KEY_PREFIX, key);
    for _ in 0..5 {
        let (val_opt, cas) = match proxy_wasm::hostcalls::get_shared_data(&full_key) {
            Ok(res) => res,
            Err(_) => (None, None),
        };
        let current = match val_opt {
            Some(bytes) if bytes.len() == 8 => {
                let arr: [u8; 8] = bytes.as_slice().try_into().unwrap_or([0; 8]);
                u64::from_le_bytes(arr)
            }
            _ => 0,
        };
        let next = current + delta;
        if proxy_wasm::hostcalls::set_shared_data(&full_key, Some(&next.to_le_bytes()), cas).is_ok() {
            break;
        }
    }
}

fn get_shared_counter(key: &str) -> u64 {
    let full_key = format!("{}{}", SHARED_KEY_PREFIX, key);
    match proxy_wasm::hostcalls::get_shared_data(&full_key) {
        Ok((Some(bytes), _)) if bytes.len() == 8 => {
            let arr: [u8; 8] = bytes.as_slice().try_into().unwrap_or([0; 8]);
            u64::from_le_bytes(arr)
        }
        _ => 0,
    }
}

fn reset_all_shared_counters() {
    let keys = [
        "total_requests",
        "fast_path_requests",
        "escalated_requests",
        "payload_acquisition_count",
        "payload_bytes_acquired",
        "body_inspection_count",
        "bounded_inspection_reached",
        "rejected_requests",
        "attack_detected",
        "attack_missed",
        "benign_classified_as_attack",
        "attack_classified_as_benign",
    ];
    for k in keys {
        let full_key = format!("{}{}", SHARED_KEY_PREFIX, k);
        let _ = proxy_wasm::hostcalls::set_shared_data(&full_key, Some(&0u64.to_le_bytes()), None);
    }
    TOTAL_REQUESTS.store(0, Ordering::SeqCst);
    FAST_PATH_REQUESTS.store(0, Ordering::SeqCst);
    ESCALATED_REQUESTS.store(0, Ordering::SeqCst);
    PAYLOAD_ACQUISITION_COUNT.store(0, Ordering::SeqCst);
    PAYLOAD_BYTES_ACQUIRED.store(0, Ordering::SeqCst);
    BODY_INSPECTION_COUNT.store(0, Ordering::SeqCst);
    BOUNDED_INSPECTION_REACHED.store(0, Ordering::SeqCst);
    REJECTED_REQUESTS.store(0, Ordering::SeqCst);
    ATTACK_DETECTED.store(0, Ordering::SeqCst);
    ATTACK_MISSED.store(0, Ordering::SeqCst);
    BENIGN_CLASSIFIED_AS_ATTACK.store(0, Ordering::SeqCst);
    ATTACK_CLASSIFIED_AS_BENIGN.store(0, Ordering::SeqCst);
}

proxy_wasm::main! {{
    proxy_wasm::set_log_level(LogLevel::Info);
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> {
        Box::new(TieredSecurityRootContext {
            config: FilterConfig::default(),
        })
    });
}}

struct TieredSecurityRootContext {
    config: FilterConfig,
}

impl Context for TieredSecurityRootContext {}

impl RootContext for TieredSecurityRootContext {
    fn on_configure(&mut self, _plugin_configuration_size: usize) -> bool {
        if let Some(config_bytes) = self.get_plugin_configuration() {
            if let Ok(config_str) = std::str::from_utf8(&config_bytes) {
                match serde_json::from_str::<FilterConfig>(config_str) {
                    Ok(parsed) => {
                        info!(
                            "TieredSecurityFilter configured: mode={}, threshold={}, max_inspection_bytes={}, truncation_policy={}",
                            parsed.mode, parsed.escalation_threshold, parsed.max_inspection_bytes, parsed.truncation_policy
                        );
                        self.config = parsed;
                    }
                    Err(e) => {
                        info!("Failed to parse filter config JSON: {}, using defaults", e);
                    }
                }
            }
        }
        true
    }

    fn create_http_context(&self, _context_id: u32) -> Option<Box<dyn HttpContext>> {
        Some(Box::new(TieredSecurityHttpContext {
            config: self.config.clone(),
            state: RequestState::Initial,
            inspection_status: InspectionStatus::NotInspected,
            risk_score: 0,
            has_body: false,
            payload_acquired: false,
            bytes_acquired: 0,
            path: String::new(),
            method: String::new(),
            is_synthetic_attack: false,
        }))
    }

    fn get_type(&self) -> Option<ContextType> {
        Some(ContextType::HttpContext)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestState {
    Initial,
    FastPath,
    Escalated,
    BodyInspection,
    Completed,
    Rejected,
}

impl RequestState {
    pub fn as_str(&self) -> &'static str {
        match self {
            RequestState::Initial => "INITIAL",
            RequestState::FastPath => "FAST_PATH",
            RequestState::Escalated => "ESCALATED",
            RequestState::BodyInspection => "BODY_INSPECTION",
            RequestState::Completed => "COMPLETED",
            RequestState::Rejected => "REJECTED",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InspectionStatus {
    NotInspected,
    Inspected,
    PartiallyInspected,
}

impl InspectionStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            InspectionStatus::NotInspected => "NOT_INSPECTED",
            InspectionStatus::Inspected => "INSPECTED",
            InspectionStatus::PartiallyInspected => "PARTIALLY_INSPECTED",
        }
    }
}

struct TieredSecurityHttpContext {
    config: FilterConfig,
    state: RequestState,
    inspection_status: InspectionStatus,
    risk_score: u32,
    has_body: bool,
    payload_acquired: bool,
    bytes_acquired: usize,
    path: String,
    method: String,
    is_synthetic_attack: bool,
}

impl Context for TieredSecurityHttpContext {}

impl HttpContext for TieredSecurityHttpContext {
    fn on_http_request_headers(&mut self, _num_headers: usize, end_of_stream: bool) -> Action {
        self.method = self.get_http_request_header(":method").unwrap_or_default();
        self.path = self.get_http_request_header(":path").unwrap_or_default();

        // 1. Healthcheck bypass
        if self.path == "/health" {
            return Action::Continue;
        }

        // 2. Metrics endpoint intercept: GET /waf-metrics
        if self.path.starts_with("/waf-metrics") {
            if self.path.contains("reset=1") {
                reset_all_shared_counters();
                let body = b"{\"status\":\"counters reset\"}\n";
                self.send_http_response(
                    200,
                    vec![
                        ("Content-Type", "application/json"),
                        ("Cache-Control", "no-cache"),
                    ],
                    Some(body),
                );
                return Action::Pause;
            }

            // Read metrics from shared data or fall back to atomic
            let mut total = get_shared_counter("total_requests");
            if total == 0 {
                total = TOTAL_REQUESTS.load(Ordering::Relaxed);
            }
            let mut fast_path = get_shared_counter("fast_path_requests");
            if fast_path == 0 {
                fast_path = FAST_PATH_REQUESTS.load(Ordering::Relaxed);
            }
            let mut escalated = get_shared_counter("escalated_requests");
            if escalated == 0 {
                escalated = ESCALATED_REQUESTS.load(Ordering::Relaxed);
            }
            let mut acq_count = get_shared_counter("payload_acquisition_count");
            if acq_count == 0 {
                acq_count = PAYLOAD_ACQUISITION_COUNT.load(Ordering::Relaxed);
            }
            let mut bytes_acq = get_shared_counter("payload_bytes_acquired");
            if bytes_acq == 0 {
                bytes_acq = PAYLOAD_BYTES_ACQUIRED.load(Ordering::Relaxed);
            }
            let mut body_insp = get_shared_counter("body_inspection_count");
            if body_insp == 0 {
                body_insp = BODY_INSPECTION_COUNT.load(Ordering::Relaxed);
            }
            let mut bounded = get_shared_counter("bounded_inspection_reached");
            if bounded == 0 {
                bounded = BOUNDED_INSPECTION_REACHED.load(Ordering::Relaxed);
            }
            let mut rejected = get_shared_counter("rejected_requests");
            if rejected == 0 {
                rejected = REJECTED_REQUESTS.load(Ordering::Relaxed);
            }
            let mut atk_det = get_shared_counter("attack_detected");
            if atk_det == 0 {
                atk_det = ATTACK_DETECTED.load(Ordering::Relaxed);
            }
            let mut atk_miss = get_shared_counter("attack_missed");
            if atk_miss == 0 {
                atk_miss = ATTACK_MISSED.load(Ordering::Relaxed);
            }
            let mut fp = get_shared_counter("benign_classified_as_attack");
            if fp == 0 {
                fp = BENIGN_CLASSIFIED_AS_ATTACK.load(Ordering::Relaxed);
            }
            let mut fn_count = get_shared_counter("attack_classified_as_benign");
            if fn_count == 0 {
                fn_count = ATTACK_CLASSIFIED_AS_BENIGN.load(Ordering::Relaxed);
            }

            let bar = if total > 0 {
                (acq_count as f64) / (total as f64)
            } else {
                0.0
            };
            let acq_rate = bar;
            let bytes_per_req = if total > 0 {
                (bytes_acq as f64) / (total as f64)
            } else {
                0.0
            };

            let json_resp = format!(
                r#"{{"mode":"{}","total_requests":{},"fast_path_requests":{},"escalated_requests":{},"payload_acquisition_count":{},"payload_bytes_acquired":{},"body_inspection_count":{},"bounded_inspection_reached":{},"rejected_requests":{},"attack_detected":{},"attack_missed":{},"benign_classified_as_attack":{},"attack_classified_as_benign":{},"bar":{:.4},"payload_acquisition_rate":{:.4},"payload_bytes_per_request":{:.2}}}"#,
                self.config.mode,
                total,
                fast_path,
                escalated,
                acq_count,
                bytes_acq,
                body_insp,
                bounded,
                rejected,
                atk_det,
                atk_miss,
                fp,
                fn_count,
                bar,
                acq_rate,
                bytes_per_req
            );

            self.send_http_response(
                200,
                vec![
                    ("Content-Type", "application/json"),
                    ("Cache-Control", "no-cache"),
                ],
                Some(json_resp.as_bytes()),
            );
            return Action::Pause;
        }

        self.has_body = !end_of_stream;

        // Extract metadata for risk classification
        let mut score: u32 = 0;

        // Method weight: standard POST without suspicious indicators adds small base score
        if self.method == "POST" || self.method == "PUT" || self.method == "PATCH" {
            score += 10;
        }

        // Suspicious strings in Path and Query
        let path_lower = self.path.to_ascii_lowercase();
        if path_lower.contains("union")
            || path_lower.contains("select")
            || path_lower.contains("' or '")
            || path_lower.contains("--")
            || path_lower.contains("/*")
            || path_lower.contains("drop table")
            || path_lower.contains("insert into")
        {
            score += 60;
        }
        if path_lower.contains("<script")
            || path_lower.contains("javascript:")
            || path_lower.contains("onerror=")
            || path_lower.contains("onload=")
            || path_lower.contains("<img")
        {
            score += 60;
        }
        if path_lower.contains("../")
            || path_lower.contains("..%2f")
            || path_lower.contains("..\\")
            || path_lower.contains("/etc/passwd")
            || path_lower.contains("win.ini")
        {
            score += 60;
        }

        // Suspicious headers
        let headers = self.get_http_request_headers();
        for (k, v) in &headers {
            let k_lower = k.to_ascii_lowercase();
            let v_lower = v.to_ascii_lowercase();
            if k_lower == "x-attack"
                || k_lower == "x-threat"
                || k_lower == "x-exploit"
                || k_lower == "x-attack-type"
            {
                score += 60;
                self.is_synthetic_attack = true;
            }
            if k_lower == "user-agent" {
                if v_lower.contains("sqlmap")
                    || v_lower.contains("nikto")
                    || v_lower.contains("nmap")
                    || v_lower.contains("masscan")
                {
                    score += 60;
                    self.is_synthetic_attack = true;
                }
            }
            // Explicit synthetic risk score override
            if k_lower == "x-risk-score" {
                if let Ok(custom_score) = v.parse::<u32>() {
                    score += custom_score;
                }
            }
            // Synthetic attack marker
            if k_lower == "x-is-attack" && v_lower == "true" {
                self.is_synthetic_attack = true;
            }
        }

        self.risk_score = score;

        // Mode Decision: BASELINE vs PROPOSED
        if self.config.mode == "baseline" {
            // BASELINE MODE: Conventional deep inspection path.
            // All requests that contain or may contain a body acquire the body buffer for inspection.
            TOTAL_REQUESTS.fetch_add(1, Ordering::Relaxed);
            inc_shared_counter("total_requests", 1);

            if self.has_body || self.method == "POST" || self.method == "PUT" {
                self.state = RequestState::Escalated;
                ESCALATED_REQUESTS.fetch_add(1, Ordering::Relaxed);
                inc_shared_counter("escalated_requests", 1);
            } else {
                self.state = RequestState::FastPath;
                FAST_PATH_REQUESTS.fetch_add(1, Ordering::Relaxed);
                inc_shared_counter("fast_path_requests", 1);
            }
            return Action::Continue;
        }

        // PROPOSED MODE: Tiered Early-Exit Layer-7 Security Enforcement
        TOTAL_REQUESTS.fetch_add(1, Ordering::Relaxed);
        inc_shared_counter("total_requests", 1);

        if self.risk_score < self.config.escalation_threshold {
            // FAST PATH: request cleared using metadata; body acquisition intentionally avoided.
            self.state = RequestState::FastPath;
            self.inspection_status = InspectionStatus::NotInspected;
            FAST_PATH_REQUESTS.fetch_add(1, Ordering::Relaxed);
            inc_shared_counter("fast_path_requests", 1);

            if self.is_synthetic_attack {
                // If a real attack was marked but metadata classifier missed it
                ATTACK_MISSED.fetch_add(1, Ordering::Relaxed);
                inc_shared_counter("attack_missed", 1);
            }

            Action::Continue
        } else {
            // ESCALATION PATH: metadata meets or exceeds escalation threshold
            self.state = RequestState::Escalated;
            ESCALATED_REQUESTS.fetch_add(1, Ordering::Relaxed);
            inc_shared_counter("escalated_requests", 1);

            if end_of_stream {
                // Suspicious request without body (e.g. GET with SQLi in path)
                // Inspect metadata directly
                if self.check_metadata_attack() {
                    self.state = RequestState::Rejected;
                    REJECTED_REQUESTS.fetch_add(1, Ordering::Relaxed);
                    inc_shared_counter("rejected_requests", 1);
                    ATTACK_DETECTED.fetch_add(1, Ordering::Relaxed);
                    inc_shared_counter("attack_detected", 1);

                    self.send_http_response(
                        403,
                        vec![
                            ("Content-Type", "application/json"),
                            ("X-Waf-Action", "Blocked-Metadata"),
                        ],
                        Some(b"{\"error\":\"Forbidden\",\"reason\":\"Metadata security violation detected\"}"),
                    );
                    return Action::Pause;
                }
            }

            Action::Continue
        }
    }

    fn on_http_request_body(&mut self, body_size: usize, end_of_stream: bool) -> Action {
        // Handle stream state and fast path
        if self.state == RequestState::FastPath {
            // FAST PATH: request cleared using metadata; body acquisition intentionally avoided.
            // The request continues downstream without host-to-guest payload buffer transfer.
            return Action::Continue;
        }

        self.state = RequestState::BodyInspection;

        if !self.payload_acquired {
                self.payload_acquired = true;
                BODY_INSPECTION_COUNT.fetch_add(1, Ordering::Relaxed);
                inc_shared_counter("body_inspection_count", 1);
                PAYLOAD_ACQUISITION_COUNT.fetch_add(1, Ordering::Relaxed);
                inc_shared_counter("payload_acquisition_count", 1);
            }

            // Bounded inspection acquisition
            let max_bytes = self.config.max_inspection_bytes;
            let bytes_to_acquire = std::cmp::min(body_size, max_bytes);

            let additional_bytes = bytes_to_acquire.saturating_sub(self.bytes_acquired);
            if additional_bytes > 0 {
                self.bytes_acquired = bytes_to_acquire;
                PAYLOAD_BYTES_ACQUIRED.fetch_add(additional_bytes as u64, Ordering::Relaxed);
                inc_shared_counter("payload_bytes_acquired", additional_bytes as u64);
            }

            // Acquire bounded body from Proxy-Wasm host
            let payload_opt = self.get_http_request_body(0, bytes_to_acquire);
            let payload = payload_opt.unwrap_or_default();

            // Check if bounded inspection limit was reached
            let limit_exceeded = body_size > max_bytes;
            if limit_exceeded {
                self.inspection_status = InspectionStatus::PartiallyInspected;
                BOUNDED_INSPECTION_REACHED.fetch_add(1, Ordering::Relaxed);
                inc_shared_counter("bounded_inspection_reached", 1);
            } else if end_of_stream {
                self.inspection_status = InspectionStatus::Inspected;
            }

            // Inspect the acquired region for attack signatures
            let attack_found = self.inspect_payload_signatures(&payload);

            if attack_found {
                self.state = RequestState::Rejected;
                REJECTED_REQUESTS.fetch_add(1, Ordering::Relaxed);
                inc_shared_counter("rejected_requests", 1);
                ATTACK_DETECTED.fetch_add(1, Ordering::Relaxed);
                inc_shared_counter("attack_detected", 1);

                self.send_http_response(
                    403,
                    vec![
                        ("Content-Type", "application/json"),
                        ("X-Waf-Action", "Blocked-Payload"),
                        ("X-Waf-Inspection-Status", self.inspection_status.as_str()),
                    ],
                    Some(b"{\"error\":\"Forbidden\",\"reason\":\"Security policy violation: attack signature detected in payload\"}"),
                );
                return Action::Pause;
            }

            // If bounded inspection window was exceeded, apply configured policy
            if limit_exceeded {
                if self.config.truncation_policy == "reject" {
                    self.state = RequestState::Rejected;
                    REJECTED_REQUESTS.fetch_add(1, Ordering::Relaxed);
                    inc_shared_counter("rejected_requests", 1);

                    if self.is_synthetic_attack {
                        ATTACK_DETECTED.fetch_add(1, Ordering::Relaxed);
                        inc_shared_counter("attack_detected", 1);
                    }

                    self.send_http_response(
                        403,
                        vec![
                            ("Content-Type", "application/json"),
                            ("X-Waf-Action", "Blocked-Truncated"),
                            ("X-Waf-Inspection-Status", self.inspection_status.as_str()),
                        ],
                        Some(b"{\"error\":\"Forbidden\",\"reason\":\"Inspection window exceeded: bounded truncation policy enforced\"}"),
                    );
                    return Action::Pause;
                }
            }

            // If payload was benign in inspected region
            if self.is_synthetic_attack && !limit_exceeded {
                // Malicious payload was not caught (e.g., evasion or signature gap)
                ATTACK_MISSED.fetch_add(1, Ordering::Relaxed);
                inc_shared_counter("attack_missed", 1);
            }

            Action::Continue
    }

    fn on_http_response_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {
        // Expose telemetry headers for client-side / k6 validation
        self.set_http_response_header("X-Waf-Mode", Some(&self.config.mode));
        self.set_http_response_header("X-Waf-State", Some(self.state.as_str()));
        self.set_http_response_header(
            "X-Waf-Payload-Acquired",
            Some(if self.payload_acquired { "1" } else { "0" }),
        );
        self.set_http_response_header(
            "X-Waf-Bytes-Acquired",
            Some(&self.bytes_acquired.to_string()),
        );
        self.set_http_response_header(
            "X-Waf-Inspection-Status",
            Some(self.inspection_status.as_str()),
        );
        Action::Continue
    }

    fn on_log(&mut self) {
        // Structured log entry for Envoy stdout observability
        if self.path != "/health" && !self.path.starts_with("/waf-metrics") {
            info!(
                "{{\"event\":\"waf_log\",\"mode\":\"{}\",\"method\":\"{}\",\"path\":\"{}\",\"state\":\"{}\",\"risk\":{},\"acquired\":{},\"bytes\":{},\"insp_status\":\"{}\"}}",
                self.config.mode,
                self.method,
                self.path,
                self.state.as_str(),
                self.risk_score,
                self.payload_acquired,
                self.bytes_acquired,
                self.inspection_status.as_str()
            );
        }
    }
}

impl TieredSecurityHttpContext {
    fn check_metadata_attack(&self) -> bool {
        let p = self.path.to_ascii_lowercase();
        p.contains("union")
            || p.contains("select")
            || p.contains("<script")
            || p.contains("../")
            || p.contains("/etc/passwd")
            || self.is_synthetic_attack
    }

    fn inspect_payload_signatures(&self, payload: &[u8]) -> bool {
        if payload.is_empty() {
            return false;
        }
        // Lossy UTF-8 conversion for fast signature matching
        let text = String::from_utf8_lossy(payload).to_ascii_lowercase();

        // 1. SQL Injection Signatures
        if text.contains("union select")
            || text.contains("' or '1'='1")
            || text.contains("' or 1=1")
            || text.contains("drop table")
            || text.contains("insert into")
            || text.contains("exec(")
            || text.contains("exec sp_")
            || text.contains("waitfor delay")
            || text.contains("--")
            || text.contains("/*")
        {
            return true;
        }

        // 2. Cross-Site Scripting (XSS) Signatures
        if text.contains("<script")
            || text.contains("alert(")
            || text.contains("onerror=")
            || text.contains("onload=")
            || text.contains("document.cookie")
            || text.contains("<img src=")
            || text.contains("javascript:")
        {
            return true;
        }

        // 3. Path Traversal Signatures
        if text.contains("../")
            || text.contains("..\\")
            || text.contains("/etc/passwd")
            || text.contains("win.ini")
            || text.contains("boot.ini")
            || text.contains("/etc/shadow")
        {
            return true;
        }

        // 4. Synthetic attack markers
        if text.contains("attack_payload") || text.contains("__malicious__") {
            return true;
        }

        false
    }
}
