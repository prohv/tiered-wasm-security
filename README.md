# Tiered Early-Exit Layer-7 WebAssembly Security Enforcement

A minimal, technically credible prototype and experimental benchmark comparing **conventional deep-inspection payload acquisition** against **tiered early-exit WebAssembly security enforcement** in an Envoy reverse proxy environment.

---

## 1. Core Architecture

```
                Client / k6 Workload
                         |
                         v
              +--------------------+
              |       Envoy        |
              |   Reverse Proxy    |
              |   (WASM Host)      |
              +---------+----------+
                        |
            Proxy-Wasm Filter (Rust)
                        |
            [on_http_request_headers]
            Risk Score < ESCALATION_THRESHOLD?
                        |
          +-------------+-------------+
          |                           |
      [YES: FAST PATH]        [NO: ESCALATION]
          |                           |
   Zero body access           Bounded body access
   get_http_request_body()    min(body_size, MAX_INSPECTION_BYTES)
   intentionally avoided      Signatures & Truncation evaluated
          |                           |
          +-------------+-------------+
                        |
                        v
                Go HTTP Backend (:8081)
```

### Key Mechanisms:
- **Fast Path**: Requests classified as benign during metadata inspection (HTTP method, query parameters, URI path, headers) immediately return `Action::Continue`. Host-to-guest body acquisition buffer transfers (`get_http_request_body`) are intentionally avoided.
- **Escalation Path**: Requests meeting or exceeding `ESCALATION_THRESHOLD` (50) acquire a bounded request body window (up to `MAX_INSPECTION_BYTES` = 4096 bytes) and perform deeper security inspection for SQL Injection, XSS, and Path Traversal.
- **Bounded Inspection & Truncation Safety**: If request payload exceeds the safe inspection window, `BOUNDED_INSPECTION_REACHED` is recorded. The filter distinguishes `INSPECTED`, `PARTIALLY_INSPECTED`, and `NOT_INSPECTED`. Under the default `truncation_policy: reject`, truncated requests are safely blocked (403 Forbidden) to resist adversarial padding.
- **Baseline Mode**: Operates as a conventional deep-inspection WAF where all requests with request bodies are acquired and inspected, establishing a true comparative baseline under identical hardware, proxy, backend, and workloads.

---

## 2. Directory Structure

```
project/
  docker-compose.yml          # Multi-service setup (Envoy + Go Backend)
  envoy/
    envoy.yaml                # Envoy configuration (Proposed Mode)
    envoy_baseline.yaml       # Envoy configuration (Baseline Mode)
    active_envoy.yaml         # Active runtime config mapped to container
  filter/
    Cargo.toml                # Rust Proxy-Wasm build config
    src/
      lib.rs                  # Tiered security filter implementation
  backend/
    main.go                   # Go HTTP backend service
    go.mod                    # Backend module definition
    Dockerfile                # Multi-stage alpine build
  tests/
    k6/
      baseline.js             # Basic load validation
      exp01.js                # EXP-01: 100% benign traffic (1KB, 4KB, 16KB, 64KB)
      exp02.js                # EXP-02: 99% benign / 1% attack (4KB)
      exp03.js                # EXP-03: 90% benign / 10% attack (1KB to 32KB)
      exp04.js                # EXP-04: 50% benign / 50% attack (4KB)
      exp05.js                # EXP-05: Synthesized attack categories (SQLi, XSS, Traversal)
      exp06.js                # EXP-06: Adversarial padding beyond window (16KB to 128KB)
  scripts/
    run_experiments.py        # Automated benchmark runner for EXP-01..06
    summarize_results.py      # Generates summary CSV, Markdown, and comparative deltas
  results/
    raw/                      # Raw per-run JSON metrics and k6 outputs
    summary/                  # Compiled CSV and Markdown tables
    execution.log             # Full timestamped benchmark execution log
    EXPERIMENT_EXECUTION_LOCK.log # Execution freeze marker (DO NOT RE-RUN)
  EXPERIMENT_REPORT.md        # Comprehensive technical report
  README.md                   # This document
```

---

## 3. Metrics Definitions

- **BAR (Buffer Acquisition Ratio)**:
  $$\text{BAR} = \frac{N_{\text{acq}}}{N_{\text{total}}} = \frac{\text{Payload Acquisition Count}}{\text{Total Requests}}$$

  Measures the fraction of requests that incurred a host-to-guest body acquisition.
- **Payload Acquisition Rate**: Rate of payload acquisition events per total requests.
- **Payload Bytes Per Request**: Total bytes copied across the WebAssembly boundary divided by total requests.
- **Latency Percentiles**: `p50`, `p95`, `p99` response latencies measured from the client perspective via k6.
- **Throughput (RPS)**: Sustained requests per second served by Envoy and backend.
- **Resource Utilization**: Container CPU utilization percentage and RSS memory (MiB) via Docker stats.
- **Detection Metrics**:
  - $\text{TPR} = \frac{\text{TP}}{\text{TP} + \text{FN}}$ (True Positive Rate / Recall)
  - $\text{FPR} = \frac{\text{FP}}{\text{FP} + \text{TN}}$ (False Positive Rate)
  - $\text{Precision} = \frac{\text{TP}}{\text{TP} + \text{FP}}$

---

## 4. Build and Run Commands

### 1. Build the Rust WebAssembly Filter
```powershell
cd filter
cargo build --target wasm32-wasip1 --release
cd ..
```

### 2. Start the Environment
```powershell
Copy-Item envoy/envoy.yaml envoy/active_envoy.yaml -Force
docker compose up --build -d
```

### 3. Verify Health & Metrics Endpoints
```powershell
# Health check
curl http://localhost:10000/health

# WAF Real-Time Telemetry Metrics
curl http://localhost:10000/waf-metrics

# Reset metrics
curl http://localhost:10000/waf-metrics?reset=1
```

### 4. Run the Full Experimental Suite (EXP-01 through EXP-06)
```powershell
python scripts/run_experiments.py
python scripts/summarize_results.py
```

---

## 5. Security Limitations

1. **Experimental Prototype**: This system is designed to measure and demonstrate the latency, throughput, and memory implications of conditional payload acquisition in WebAssembly reverse proxies. It is not a complete production WebAF.
2. **Metadata Classifier Scope**: The metadata classifier relies on deterministic signature heuristics (query strings, paths, headers, methods). Advanced evasions, encoding mismatches, and obfuscations require deeper lexical analysis.
3. **Bounded Inspection Trade-Off**: Bounded payload inspection inspects only up to `MAX_INSPECTION_BYTES`. To prevent adversarial bypasses where attack payloads are placed after benign padding, the system enforces a strict truncation rejection policy (`truncation_policy: reject`), trading off the ability to accept oversized benign payloads on escalated paths for security integrity.
4. **No Zero-Copy Claim**: Proxy-Wasm host-to-guest memory transfers involve memory copies across the host-guest boundary. The performance benefit arises strictly from **avoiding unnecessary acquisition calls**, not from zero-copy memory tricks.
5. **Multipart & Parser Discrepancies**: Complex multipart/form-data payloads may split boundary tokens across inspection windows, requiring dedicated streaming parsers.
