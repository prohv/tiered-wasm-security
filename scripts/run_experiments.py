#!/usr/bin/env python3
"""
Experiment Runner for Tiered Early-Exit Layer-7 WebAssembly Security Enforcement.
Executes EXP-01 through EXP-06 under identical environments for both Baseline and Proposed modes.
Measures real latency, throughput, CPU, RSS memory, BAR, payload acquisition, and detection metrics.
"""

import json
import os
import shutil
import subprocess
import sys
import time
import urllib.request

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
RESULTS_RAW_DIR = os.path.join(PROJECT_ROOT, "results", "raw")
RESULTS_SUMMARY_DIR = os.path.join(PROJECT_ROOT, "results", "summary")
ENVOY_DIR = os.path.join(PROJECT_ROOT, "envoy")

os.makedirs(RESULTS_RAW_DIR, exist_ok=True)
os.makedirs(RESULTS_SUMMARY_DIR, exist_ok=True)

def run_cmd(cmd, cwd=PROJECT_ROOT):
    p = subprocess.run(cmd, shell=True, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return p.returncode, p.stdout.strip(), p.stderr.strip()

def switch_mode(mode):
    print(f"\n[CONFIG] Switching Envoy to mode: {mode.upper()} ...")
    src = os.path.join(ENVOY_DIR, "envoy_baseline.yaml" if mode == "baseline" else "envoy.yaml")
    dst = os.path.join(ENVOY_DIR, "active_envoy.yaml")
    shutil.copyfile(src, dst)
    
    # Recreate Envoy container with new active config
    ret, out, err = run_cmd("docker compose up -d --force-recreate envoy")
    if ret != 0:
        print(f"Error restarting envoy: {err}")
    
    # Wait for Envoy to be healthy
    for _ in range(30):
        try:
            req = urllib.request.urlopen("http://localhost:10000/health", timeout=1)
            if req.status == 200:
                break
        except Exception:
            time.sleep(0.3)
    time.sleep(1)

def reset_waf_metrics():
    try:
        urllib.request.urlopen("http://localhost:10000/waf-metrics?reset=1", timeout=2)
    except Exception as e:
        print(f"Warning: Failed to reset WAF metrics: {e}")

def get_waf_metrics():
    try:
        with urllib.request.urlopen("http://localhost:10000/waf-metrics", timeout=2) as resp:
            data = resp.read().decode('utf-8')
            return json.loads(data)
    except Exception as e:
        print(f"Error fetching WAF metrics: {e}")
        return {}

def get_docker_stats():
    ret, out, err = run_cmd("docker stats --no-stream --format \"{{.CPUPerc}}\t{{.MemUsage}}\" waf_envoy")
    if ret == 0 and out:
        parts = out.split("\t")
        cpu_str = parts[0].replace("%", "").strip()
        mem_str = parts[1].split("/")[0].strip() if len(parts) > 1 else "0MiB"
        # Convert memory to MiB float
        mem_val = 0.0
        if "GiB" in mem_str:
            mem_val = float(mem_str.replace("GiB", "").strip()) * 1024.0
        elif "MiB" in mem_str:
            mem_val = float(mem_str.replace("MiB", "").strip())
        elif "KiB" in mem_str:
            mem_val = float(mem_str.replace("KiB", "").strip()) / 1024.0
        try:
            cpu_val = float(cpu_str)
        except ValueError:
            cpu_val = 0.0
        return {"cpu_percent": cpu_val, "rss_memory_mib": round(mem_val, 2)}
    return {"cpu_percent": 0.0, "rss_memory_mib": 0.0}

def run_k6_test(script_name, env_vars, summary_json_name):
    env_str = " ".join([f"-e {k}={v}" for k, v in env_vars.items()])
    raw_path_container = f"/results/raw/{summary_json_name}"
    cmd = (
        f"docker run --rm --network cn-project_waf_net "
        f"-v \"{PROJECT_ROOT}/tests:/tests\" "
        f"-v \"{PROJECT_ROOT}/results/raw:/results/raw\" "
        f"{env_str} "
        f"grafana/k6:latest run --summary-export={raw_path_container} /tests/k6/{script_name}"
    )
    ret, out, err = run_cmd(cmd)
    if ret != 0:
        print(f"k6 execution error: {err}")
    return ret, out

def execute_experiment_run(exp_id, mode, traffic_mix, payload_size_label, payload_bytes, script_name, custom_env=None):
    tag = f"{exp_id}_{mode}_{payload_size_label.replace(' ', '').lower()}"
    summary_file = f"{tag}_k6.json"
    result_file = f"{tag}.json"
    
    print(f"\n=======================================================")
    print(f"RUNNING: {exp_id} | Mode: {mode.upper()} | Mix: {traffic_mix} | Payload: {payload_size_label}")
    print(f"=======================================================")
    
    reset_waf_metrics()
    time.sleep(0.5)
    
    stats_before = get_docker_stats()
    
    env_vars = {
        "TARGET_URL": "http://waf_envoy:10000/api/test",
        "PAYLOAD_SIZE": str(payload_bytes),
        "TEST_DURATION": "4s",
        "VUS": "10",
    }
    if custom_env:
        env_vars.update(custom_env)
        
    k6_ret, k6_output = run_k6_test(script_name, env_vars, summary_file)
    
    stats_after = get_docker_stats()
    waf_metrics = get_waf_metrics()
    
    # Parse k6 summary
    k6_summary_path = os.path.join(RESULTS_RAW_DIR, summary_file)
    k6_data = {}
    if os.path.exists(k6_summary_path):
        try:
            with open(k6_summary_path, 'r', encoding='utf-8') as f:
                k6_data = json.load(f)
        except Exception as e:
            print(f"Error reading k6 summary: {e}")
            
    metrics_block = k6_data.get("metrics", {})
    req_duration = metrics_block.get("http_req_duration", {})
    reqs_block = metrics_block.get("http_reqs", {})
    
    p50 = req_duration.get("p(50)", req_duration.get("med", 0.0))
    p95 = req_duration.get("p(95)", 0.0)
    p99 = req_duration.get("p(99)", 0.0)
    total_reqs = reqs_block.get("count", waf_metrics.get("total_requests", 0))
    rps = reqs_block.get("rate", 0.0)
    
    # CPU & RSS
    cpu = stats_after.get("cpu_percent", 0.0)
    rss = stats_after.get("rss_memory_mib", 0.0)
    
    # Security Detection Metrics
    # In k6 custom counters:
    # attacks_sent, attacks_blocked, benign_sent, benign_allowed
    attacks_sent = metrics_block.get("attacks_sent", {}).get("count", 0)
    attacks_blocked = metrics_block.get("attacks_blocked", {}).get("count", waf_metrics.get("attack_detected", 0))
    benign_sent = metrics_block.get("benign_sent", {}).get("count", waf_metrics.get("fast_path_requests", 0))
    benign_allowed = metrics_block.get("benign_allowed", {}).get("count", 0)
    
    # Fallback to WAF counters if custom counters not used
    tp = attacks_blocked
    fn = max(0, attacks_sent - attacks_blocked)
    fp = waf_metrics.get("benign_classified_as_attack", 0)
    tn = benign_allowed if benign_allowed > 0 else max(0, benign_sent - fp)
    
    tpr = (tp / (tp + fn)) if (tp + fn) > 0 else 1.0 if tp > 0 else None
    fpr = (fp / (fp + tn)) if (fp + tn) > 0 else 0.0 if tn > 0 else None
    precision = (tp / (tp + fp)) if (tp + fp) > 0 else 1.0 if tp > 0 else None
    
    record = {
        "experiment": exp_id,
        "mode": mode,
        "traffic_mix": traffic_mix,
        "payload": payload_size_label,
        "payload_bytes": payload_bytes,
        "requests": total_reqs,
        "rps": round(rps, 2),
        "p50_ms": round(p50, 2),
        "p95_ms": round(p95, 2),
        "p99_ms": round(p99, 2),
        "cpu_percent": cpu,
        "rss_memory_mib": rss,
        "bar": round(waf_metrics.get("bar", 0.0), 4),
        "payload_acquisition_rate": round(waf_metrics.get("payload_acquisition_rate", 0.0), 4),
        "payload_bytes_acquired": waf_metrics.get("payload_bytes_acquired", 0),
        "payload_bytes_per_request": round(waf_metrics.get("payload_bytes_per_request", 0.0), 2),
        "fast_path_requests": waf_metrics.get("fast_path_requests", 0),
        "escalated_requests": waf_metrics.get("escalated_requests", 0),
        "bounded_inspection_reached": waf_metrics.get("bounded_inspection_reached", 0),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "tpr": round(tpr, 4) if tpr is not None else "N/A",
        "fpr": round(fpr, 4) if fpr is not None else "N/A",
        "precision": round(precision, 4) if precision is not None else "N/A",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    
    out_file = os.path.join(RESULTS_RAW_DIR, result_file)
    with open(out_file, 'w', encoding='utf-8') as f:
        json.dump(record, f, indent=2)
        
    print(f"-> DONE: Req={total_reqs}, RPS={record['rps']}, p50={record['p50_ms']}ms, BAR={record['bar']}, AcqBytes={record['payload_bytes_acquired']}")
    return record

def main():
    lock_file = os.path.join(RESULTS_SUMMARY_DIR, "..", "EXPERIMENT_EXECUTION_LOCK.log")
    lock_file = os.path.abspath(lock_file)
    if os.path.exists(lock_file) and "--force" not in sys.argv:
        print("\n" + "=" * 78)
        print("[LOCKED] EXPERIMENT EXECUTION IS FROZEN - DO NOT RE-RUN")
        print("=" * 78)
        print("All 30 benchmark runs have completed and verified results are logged.")
        print(f"Lock File: {lock_file}")
        print("Detailed Log: results/execution.log")
        print("CSV Summary:  results/summary/results_summary.csv")
        print("Report:       EXPERIMENT_REPORT.md")
        print("\nTo bypass this lock and re-run anyway, pass the '--force' flag:")
        print("  python scripts/run_experiments.py --force\n")
        print("=" * 78 + "\n")
        sys.exit(0)

    print("=== Starting Comprehensive Experimental Suite (EXP-01 -> EXP-06) ===")
    all_records = []
    
    modes = ["baseline", "proposed"]
    
    for mode in modes:
        switch_mode(mode)
        
        # ---------------- EXP-01: 100% Benign Traffic ----------------
        exp01_sizes = [
            ("1 KB", 1024),
            ("4 KB", 4096),
            ("16 KB", 16384),
            ("64 KB", 65536),
        ]
        for label, b in exp01_sizes:
            rec = execute_experiment_run("EXP-01", mode, "100% Benign", label, b, "exp01.js")
            all_records.append(rec)
            time.sleep(1)
            
        # ---------------- EXP-02: 99% Benign / 1% Attack (4 KB) ----------------
        rec = execute_experiment_run("EXP-02", mode, "99% Benign / 1% Attack", "4 KB", 4096, "exp02.js")
        all_records.append(rec)
        time.sleep(1)
        
        # ---------------- EXP-03: 90% Benign / 10% Attack (1 KB to 32 KB) ----------------
        exp03_sizes = [
            ("1 KB", 1024),
            ("4 KB", 4096),
            ("16 KB", 16384),
            ("32 KB", 32768),
        ]
        for label, b in exp03_sizes:
            rec = execute_experiment_run("EXP-03", mode, "90% Benign / 10% Attack", label, b, "exp03.js")
            all_records.append(rec)
            time.sleep(1)
            
        # ---------------- EXP-04: 50% Benign / 50% Attack (4 KB) ----------------
        rec = execute_experiment_run("EXP-04", mode, "50% Benign / 50% Attack", "4 KB", 4096, "exp04.js")
        all_records.append(rec)
        time.sleep(1)
        
        # ---------------- EXP-05: Synthesized Attack Categories ----------------
        rec = execute_experiment_run("EXP-05", mode, "SQLi, XSS, Path Traversal, Benign", "4 KB", 4096, "exp05.js")
        all_records.append(rec)
        time.sleep(1)
        
        # ---------------- EXP-06: Adversarial Padding (Window Truncation) ----------------
        exp06_sizes = [
            ("16 KB", 16384),
            ("32 KB", 32768),
            ("64 KB", 65536),
            ("128 KB", 131072),
        ]
        for label, b in exp06_sizes:
            rec = execute_experiment_run("EXP-06", mode, "Adversarial Padding Past Window", label, b, "exp06.js")
            all_records.append(rec)
            time.sleep(1)

    # Save complete merged raw dataset
    merged_path = os.path.join(RESULTS_SUMMARY_DIR, "all_experiments_raw.json")
    with open(merged_path, 'w', encoding='utf-8') as f:
        json.dump(all_records, f, indent=2)
        
    print(f"\n[COMPLETED] Executed all {len(all_records)} experiment runs.")
    print(f"Saved merged dataset to: {merged_path}")

if __name__ == "__main__":
    main()
