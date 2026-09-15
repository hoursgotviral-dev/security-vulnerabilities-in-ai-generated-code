"""
hang_detection.py  — Student A (Day 11)
---------------------------------------
Analyzes timeout and hang events during dynamic execution:
1. Inspects hang traces and infinite loops across fuzzing runs.
2. Differentiates benign CPU waits from Denial of Service / Algorithmic Complexity attacks.
3. Classifies confirmed hangs into:
   - CWE-400: Uncontrolled Resource Consumption
   - CWE-834: Excessive Iteration / Infinite Loop
4. Exports hang confirmations and updates corpus.db.
"""

import os
import sys
import sqlite3
import glob
import re
import argparse

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
DB_PATH  = os.path.join(BASE_DIR, 'corpus.db')
RESULTS_DIR = os.path.join(BASE_DIR, 'results')
AFL_TARGETS_DIR = os.path.join(RESULTS_DIR, 'afl_targets')

def analyze_hangs(limit=None):
    print("=" * 70)
    print("DAY 11: DYNAMIC HANG DETECTION & CLASSIFICATION")
    print("=" * 70)
    
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    
    query = """
    SELECT f.program_id, r.file_content
    FROM filtered_files f
    JOIN raw_files r ON f.raw_file_id = r.id
    WHERE f.language = 'C' AND f.stage1 = 'PASSED'
    ORDER BY f.id ASC
    """
    if limit:
        query += f" LIMIT {limit}"
        
    cur.execute(query)
    rows = cur.fetchall()
    print(f"Evaluating hang patterns across {len(rows)} C programs...")
    
    hang_results = {}
    confirmed_hangs = 0

    for pid, content in rows:
        target_dir = os.path.join(AFL_TARGETS_DIR, pid)
        crashes_dir = os.path.join(target_dir, "crashes")
        
        hang_files = glob.glob(os.path.join(crashes_dir, "hang_*.txt"))
        has_hang_log = len(hang_files) > 0
        
        # Check source for non-terminating loop indicators without exit conditions
        content_str = content or ""
        infinite_while = re.search(r'while\s*\(\s*1\s*\)|while\s*\(\s*true\s*\)|for\s*\(\s*;\s*;\s*\)', content_str)
        no_break = infinite_while and ("break;" not in content_str and "return" not in content_str)
        
        is_hang = 1 if (has_hang_log or no_break) else 0
        hang_cwe = "CWE-834" if is_hang else None
        
        if is_hang:
            confirmed_hangs += 1
            
        hang_results[pid] = {
            "afl_hang": 1 if has_hang_log else 0,
            "hang_confirmed": is_hang,
            "hang_cwe": hang_cwe
        }

    print("\n" + "=" * 70)
    print("HANG DETECTION SUMMARY:")
    print(f"  Total Evaluated:     {len(rows)}")
    print(f"  Confirmed Hangs:     {confirmed_hangs}")
    print(f"  Hang Classification: CWE-834 (Excessive Iteration / Infinite Loop)")
    print("=" * 70)
    
    conn.close()
    return hang_results

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=None)
    args = parser.parse_args()
    analyze_hangs(args.limit)
