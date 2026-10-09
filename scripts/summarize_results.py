#!/usr/bin/env python3
"""
Summarizer for Tiered Early-Exit Layer-7 WebAssembly Security Enforcement experiments.
Reads raw experiment measurements, computes deltas between Baseline and Proposed,
and exports structured CSV and Markdown reports.
"""

import csv
import json
import os
import sys

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
RESULTS_RAW_DIR = os.path.join(PROJECT_ROOT, "results", "raw")
RESULTS_SUMMARY_DIR = os.path.join(PROJECT_ROOT, "results", "summary")

def pct_change(proposed, baseline):
    if baseline == 0:
        return "N/A" if proposed == 0 else "+Inf%"
    val = ((proposed - baseline) / baseline) * 100.0
    prefix = "+" if val > 0 else ""
    return f"{prefix}{val:.2f}%"

def main():
    raw_merged = os.path.join(RESULTS_SUMMARY_DIR, "all_experiments_raw.json")
    if not os.path.exists(raw_merged):
        print(f"Error: {raw_merged} not found.")
        sys.exit(1)
        
    with open(raw_merged, 'r', encoding='utf-8') as f:
        records = json.load(f)
        
    # 1. Output CSV
    csv_path = os.path.join(RESULTS_SUMMARY_DIR, "results_summary.csv")
    fieldnames = [
        "Experiment", "Mode", "Traffic Mix", "Payload", "Requests", "RPS",
        "p50_ms", "p95_ms", "p99_ms", "CPU_%", "RSS_MiB", "BAR",
        "Payload_Acq_Rate", "Payload_Bytes", "Bytes_Per_Req",
        "TP", "FP", "FN", "TN", "TPR", "FPR", "Precision"
    ]
    
    with open(csv_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(fieldnames)
        for r in records:
            writer.writerow([
                r["experiment"],
                r["mode"],
                r["traffic_mix"],
                r["payload"],
                r["requests"],
                r["rps"],
                r["p50_ms"],
                r["p95_ms"],
                r["p99_ms"],
                r["cpu_percent"],
                r["rss_memory_mib"],
                r["bar"],
                r["payload_acquisition_rate"],
                r["payload_bytes_acquired"],
                r["payload_bytes_per_request"],
                r.get("tp", "N/A"),
                r.get("fp", "N/A"),
                r.get("fn", "N/A"),
                r.get("tn", "N/A"),
                r.get("tpr", "N/A"),
                r.get("fpr", "N/A"),
                r.get("precision", "N/A")
            ])
            
    print(f"Exported CSV: {csv_path}")

    # 2. Output Markdown Table
    md_path = os.path.join(RESULTS_SUMMARY_DIR, "results_summary.md")
    with open(md_path, 'w', encoding='utf-8') as f:
        f.write("# Experimental Results Summary Table\n\n")
        f.write("| Experiment | Mode | Traffic Mix | Payload | Requests | RPS | p50 (ms) | p95 (ms) | p99 (ms) | CPU (%) | RSS (MiB) | BAR | Payload Bytes | TPR | FPR | Precision |\n")
        f.write("| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n")
        for r in records:
            f.write(
                f"| {r['experiment']} | {r['mode']} | {r['traffic_mix']} | {r['payload']} | "
                f"{r['requests']} | {r['rps']:.1f} | {r['p50_ms']:.2f} | {r['p95_ms']:.2f} | {r['p99_ms']:.2f} | "
                f"{r['cpu_percent']:.1f}% | {r['rss_memory_mib']:.1f} | {r['bar']:.4f} | {r['payload_bytes_acquired']:,} | "
                f"{r.get('tpr', 'N/A')} | {r.get('fpr', 'N/A')} | {r.get('precision', 'N/A')} |\n"
            )
    print(f"Exported Markdown Summary: {md_path}")

    # 3. Output Comparative Analysis Markdown
    # Match baseline vs proposed by (experiment, payload)
    comp_path = os.path.join(RESULTS_SUMMARY_DIR, "comparison_summary.md")
    
    baseline_map = {}
    proposed_map = {}
    for r in records:
        key = (r["experiment"], r["payload"])
        if r["mode"] == "baseline":
            baseline_map[key] = r
        elif r["mode"] == "proposed":
            proposed_map[key] = r
            
    with open(comp_path, 'w', encoding='utf-8') as f:
        f.write("# Baseline vs. Proposed Comparative Analysis\n\n")
        f.write("Percentage change formula: `((proposed - baseline) / baseline) * 100`\n\n")
        f.write("Evaluation context:\n")
        f.write("- **BAR Change**: Reduction is beneficial (avoids unnecessary host-to-guest payload transfers).\n")
        f.write("- **Payload Bytes**: Reduction is beneficial (avoids buffer allocation and memory copies).\n")
        f.write("- **Latency (p50/p95/p99)**: Reduction is beneficial.\n")
        f.write("- **Throughput (RPS)**: Increase is beneficial.\n")
        f.write("- **CPU/RSS**: Reduction is beneficial.\n\n")
        f.write("| Experiment | Payload | RPS Δ | p50 Δ | p95 Δ | p99 Δ | BAR (Base → Prop) | Payload Bytes Δ | RSS Δ |\n")
        f.write("| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n")
        
        for key in sorted(baseline_map.keys()):
            if key in proposed_map:
                b = baseline_map[key]
                p = proposed_map[key]
                exp_id, payload = key
                
                rps_delta = pct_change(p["rps"], b["rps"])
                p50_delta = pct_change(p["p50_ms"], b["p50_ms"])
                p95_delta = pct_change(p["p95_ms"], b["p95_ms"])
                p99_delta = pct_change(p["p99_ms"], b["p99_ms"])
                bar_str = f"{b['bar']:.4f} → {p['bar']:.4f}"
                bytes_delta = pct_change(p["payload_bytes_acquired"], b["payload_bytes_acquired"])
                rss_delta = pct_change(p["rss_memory_mib"], b["rss_memory_mib"])
                
                f.write(f"| {exp_id} | {payload} | {rps_delta} | {p50_delta} | {p95_delta} | {p99_delta} | {bar_str} | {bytes_delta} | {rss_delta} |\n")
                
    print(f"Exported Comparative Analysis: {comp_path}")

if __name__ == "__main__":
    main()
