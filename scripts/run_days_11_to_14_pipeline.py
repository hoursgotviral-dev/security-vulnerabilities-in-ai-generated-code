"""
run_days_11_to_14_pipeline.py
------------------------------
Master orchestrator executing the 100% empirical research pipeline for Days 11 through 14:
- Day 11: Dynamic integration prep, AFL++ batches 1-3, MSan/differential, crash deduplication, edge coverage, hang detection.
- Day 12: Overconfidence proxy (5,600 evaluations), overconfidence summary, Atheris fuzzing, taint tracker, two-rater consensus.
- Days 13-14: Three-Pillar matrix reconstruction, headline metrics calculation, coverage violin plot, UpSet overlap plot, CWE heatmap.
"""

import os
import sys
import subprocess
import argparse

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
SCRIPTS_DIR = os.path.join(BASE_DIR, 'scripts')

def run_step(script_name, description, extra_args=None):
    print(f"\n{'='*70}")
    print(f"Executing: {description} ({script_name})")
    print(f"{'='*70}")
    
    script_path = os.path.join(SCRIPTS_DIR, script_name)
    cmd = [sys.executable, script_path]
    if extra_args:
        cmd.extend(extra_args)
        
    res = subprocess.run(cmd)
    if res.returncode != 0:
        print(f"Warning: {script_name} exited with status {res.returncode}")

def run_all(limit=None):
    print("======================================================================")
    print("STARTING DAYS 11 - 14 DYNAMIC ANALYSIS & THREE-PILLAR PIPELINE")
    print("======================================================================")
    
    limit_args = ['--limit', str(limit)] if limit else []
    
    # Day 11
    run_step("integration_prep.py", "Day 11 — Integration Preparation & Harness Generation", limit_args)
    
    # Day 12 Dynamic Suite
    run_step("dynamic_summary.py", "Day 11/12 — Multi-Tool Dynamic Analysis & Ingestion")
    run_step("run_overconfidence_proxy.py", "Day 12 — Overconfidence Proxy (5,600 Evals)")
    run_step("overconfidence_summary.py", "Day 12 — Overconfidence Metric Aggregation")
    run_step("two_rater_taint_review.py", "Day 12 — Two-Rater Taint Review & Cohen's Kappa")
    
    # Days 13-14 Integration & Headline Metrics
    run_step("build_pillar_matrix.py", "Days 13-14 — Three-Pillar Matrix Reconstruction")
    run_step("compute_headline_metrics.py", "Days 13-14 — Empirical Headline Metrics Computation")
    run_step("coverage_violin.py", "Days 13-14 — Edge Coverage Violin Visualization")
    run_step("upset_plot.py", "Days 13-14 — Three-Pillar Overlap Distribution Plot")
    run_step("cwe_heatmap.py", "Days 13-14 — Top CWE Frequency Heatmap")
    
    print("\n======================================================================")
    print("DAYS 11 - 14 PIPELINE COMPLETED SUCCESSFULLY!")
    print("======================================================================")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=None, help="Sample limit for intensive steps")
    args = parser.parse_args()
    run_all(limit=args.limit)
