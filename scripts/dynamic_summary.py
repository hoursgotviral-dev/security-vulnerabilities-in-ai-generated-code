"""
dynamic_summary.py  — Student A & B (Day 12)
---------------------------------------------
Master dynamic analysis ingester and summary generator:
1. Ingests AFL++ crashes, MSan results, Atheris fuzzing, Taint Tracking, and Hangs.
2. Updates `dynamic_results` table in `corpus.db`.
3. Computes:
   - Dynamic crash rate (C)
   - Dynamic injection / exception rate (Python & JS)
   - Dynamic CWE distribution
   - Mean edge coverage
4. Exports results to results/dynamic_summary.json.
"""

import os
import sys
import sqlite3
import json
import glob
import re

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
DB_PATH  = os.path.join(BASE_DIR, 'corpus.db')
RESULTS_DIR = os.path.join(BASE_DIR, 'results')
os.makedirs(RESULTS_DIR, exist_ok=True)

# Import submodule functions
from run_afl_batches import run_afl_batches
from run_libfuzzer_msan import run_differential_pass
from deduplicate_crashes import deduplicate_all_crashes
from edge_coverage import compute_edge_coverage
from hang_detection import analyze_hangs
from run_atheris_fuzzing import run_python_fuzzing
from taint_tracker import analyze_taint

def run_dynamic_pipeline_and_summary(limit=None):
    print("=" * 70)
    print("DAY 12: RUNNING UNIFIED DYNAMIC ANALYSIS PIPELINE")
    print("=" * 70)
    
    # Run submodules
    crashed_pids, hang_pids = run_afl_batches(limit)
    diff_results = run_differential_pass(limit)
    crashes_summary = deduplicate_all_crashes(limit)
    coverage_map = compute_edge_coverage(limit)
    hang_map = analyze_hangs(limit)
    py_fuzz_map = run_python_fuzzing(limit)
    taint_map = analyze_taint(limit)
    
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    
    cur.execute("DELETE FROM dynamic_results")
    conn.commit()
    
    # Query all passed filtered files
    cur.execute("""
    SELECT program_id, language, model
    FROM filtered_files
    WHERE stage1 = 'PASSED'
    ORDER BY id ASC
    """)
    rows = cur.fetchall()
    print(f"\nPopulating dynamic_results table for {len(rows)} programs...")
    
    cwe_dist = {}
    total_c_crashes = 0
    total_py_injections = 0
    total_hangs = 0

    for pid, lang, model in rows:
        afl_c = 1 if pid in crashed_pids or (pid in crashes_summary and crashes_summary[pid].get("crashed")) else 0
        diff_info = diff_results.get(pid, {})
        msan_res = diff_info.get("msan_result", "CLEAN")
        libfuzzer_diff = diff_info.get("libfuzzer_differential", 0)
        
        crash_info = crashes_summary.get(pid, {})
        conf_count = crash_info.get("confirmed_count", 1 if afl_c else 0)
        u_hashes = json.dumps(crash_info.get("unique_hashes", [])) if crash_info.get("unique_hashes") else None
        dynamic_cwe = crash_info.get("dynamic_cwe", "CWE-119" if afl_c else None)
        
        h_info = hang_map.get(pid, {})
        afl_h = h_info.get("afl_hang", 0)
        h_conf = h_info.get("hang_confirmed", 0)
        h_cwe = h_info.get("hang_cwe")
        
        cov_pct = coverage_map.get(pid, 50.0)
        
        py_info = py_fuzz_map.get(pid, {})
        ath_crashed = py_info.get("atheris_crashed", 0)
        ath_exc = py_info.get("atheris_exception_type")
        
        t_info = taint_map.get(pid, {})
        t_flows = t_info.get("taint_flows")
        inj_conf = t_info.get("final_injection_confirmed", 0)
        
        if lang == 'Python' or lang == 'JavaScript':
            if inj_conf or ath_crashed:
                total_py_injections += 1
                if not dynamic_cwe:
                    dynamic_cwe = "CWE-89" if "SQL" in str(t_flows) else ("CWE-78" if "system" in str(t_flows) else "CWE-94")
        else:
            if afl_c:
                total_c_crashes += 1
                
        if h_conf:
            total_hangs += 1

        if dynamic_cwe:
            cwe_dist[dynamic_cwe] = cwe_dist.get(dynamic_cwe, 0) + 1
            
        classification = "DYNAMIC_CONFIRMED" if (afl_c or inj_conf or ath_crashed or h_conf) else "DYNAMIC_CLEAN"

        cur.execute("""
        INSERT INTO dynamic_results
        (program_id, afl_crashed, afl_hang, confirmed_crash_count, unique_crash_hashes,
         dynamic_cwe, hang_cwe, hang_confirmed, edge_coverage_pct, msan_result,
         atheris_crashed, atheris_exception_type, taint_flows, final_injection_confirmed,
         libfuzzer_differential, classification)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (pid, afl_c, afl_h, conf_count, u_hashes, dynamic_cwe, h_cwe, h_conf, cov_pct,
              msan_res, ath_crashed, ath_exc, t_flows, inj_conf, libfuzzer_diff, classification))

    conn.commit()
    
    # Calculate summary metrics
    total_programs = len(rows)
    c_count = len([r for r in rows if r[1] == 'C'])
    py_count = len([r for r in rows if r[1] == 'Python'])
    
    summary = {
        "total_programs_analyzed": total_programs,
        "c_programs_count": c_count,
        "python_programs_count": py_count,
        "c_programs_crashed_count": total_c_crashes,
        "c_crash_rate_pct": round((total_c_crashes / max(c_count, 1)) * 100, 2),
        "python_injection_triggers_count": total_py_injections,
        "python_injection_rate_pct": round((total_py_injections / max(py_count, 1)) * 100, 2),
        "confirmed_hangs_count": total_hangs,
        "mean_edge_coverage_pct": round(sum(coverage_map.values()) / max(len(coverage_map), 1), 2),
        "dynamic_cwe_distribution": cwe_dist
    }
    
    out_json = os.path.join(RESULTS_DIR, "dynamic_summary.json")
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=4)
        
    print("\n" + "=" * 70)
    print("DYNAMIC ANALYSIS PIPELINE COMPLETE:")
    print(f"  Summary saved to:               {out_json}")
    print(f"  Total Programs Evaluated:       {total_programs}")
    print(f"  C AFL++ Crash Rate:             {summary['c_crash_rate_pct']}% ({total_c_crashes}/{c_count})")
    print(f"  Python/JS Injection Rate:       {summary['python_injection_rate_pct']}% ({total_py_injections}/{py_count})")
    print(f"  Mean Edge Coverage:             {summary['mean_edge_coverage_pct']}%")
    print("=" * 70)
    
    conn.close()
    return summary

if __name__ == "__main__":
    run_dynamic_pipeline_and_summary()
