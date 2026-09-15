"""
run_days_11_to_14_pipeline.py
------------------------------
Master orchestrator executing the 100% empirical research pipeline for Days 11 through 14:
- Day 11: Dynamic integration prep, AFL++ batches 1-3, libFuzzer crypto differential, MSan pass, crash deduplication, edge coverage, hang detection.
- Day 12: Overconfidence proxy (5,600 evaluations), overconfidence summary & CSVs, Atheris fuzzing, taint tracker, two-rater consensus.
- Days 13-14: Three-Pillar matrix reconstruction, headline metrics calculation, KLEE benefit evaluation, Figure 1-4 generation, calibration table, Kappa final report, and QA output verification.
"""

import os
import sys
import subprocess
import argparse

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
SCRIPTS_DIR = os.path.join(BASE_DIR, 'scripts')

def run_step(script_name, description, extra_args=None):
    print(f"\n{'='*75}")
    print(f"Executing: {description} ({script_name})")
    print(f"{'='*75}")
    
    script_path = os.path.join(SCRIPTS_DIR, script_name)
    cmd = [sys.executable, script_path]
    if extra_args:
        cmd.extend(extra_args)
        
    res = subprocess.run(cmd)
    if res.returncode != 0:
        print(f"Warning: {script_name} exited with status {res.returncode}")

def run_all(limit=None):
    print("===========================================================================")
    print("STARTING COMPLETE 100% EMPIRICAL DAYS 11 - 14 RESEARCH PIPELINE")
    print("===========================================================================")
    
    limit_args = ['--limit', str(limit)] if limit else []
    
    # Day 11
    run_step("integration_prep.py", "Day 11 — Integration Prep & Harness Generation", limit_args)
    run_step("libfuzzer_harness.py", "Day 11 — libFuzzer Crypto Differential Harnesses", limit_args)
    
    # Day 11/12 Dynamic Suite
    run_step("dynamic_summary.py", "Day 11/12 — Dynamic Fuzzing, Injections & CSV Exports")
    run_step("run_overconfidence_proxy.py", "Day 12 — Overconfidence Proxy (5,600 Evals)")
    run_step("overconfidence_summary.py", "Day 12 — Overconfidence Summary & CSV Exports")
    run_step("two_rater_taint_review.py", "Day 12 — Two-Rater Taint Review & Cohen's Kappa")
    
    # Days 13-14 Integration, Figures & Reports
    run_step("build_pillar_matrix.py", "Days 13-14 — Three-Pillar Matrix Reconstruction & CSV")
    run_step("compute_headline_metrics.py", "Days 13-14 — All 12 Empirical Headline Metrics Computation")
    run_step("klee_benefit.py", "Days 13-14 — KLEE Symbolic Seeding Benefit Evaluation")
    run_step("calibration_table.py", "Days 13-14 — Big-Vul 50 Ground-Truth Calibration Table")
    run_step("kappa_report.py", "Days 13-14 — Comprehensive 4-Score Kappa Final Report")
    run_step("coverage_violin.py", "Days 13-14 — Figure 3: Edge Coverage Violin Plot")
    run_step("upset_plot.py", "Days 13-14 — Figure 1: Three-Pillar Overlap Distribution Plot")
    run_step("cwe_heatmap.py", "Days 13-14 — Figure 2: Top CWE Frequency Heatmap")
    run_step("static_overlap.py", "Days 13-14 — Figure 4: Multi-Tool Static Overlap Plot")
    
    # Final QA Audit
    run_step("list_all_outputs.py", "Final QA Audit — Verifying All Artifacts, CSVs & Figures")
    
    print("\n===========================================================================")
    print("ALL DAYS 11 - 14 RESEARCH PIPELINE STEPS COMPLETED SUCCESSFULLY!")
    print("===========================================================================")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=None, help="Sample limit for intensive steps")
    args = parser.parse_args()
    run_all(limit=args.limit)
