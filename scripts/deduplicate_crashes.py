"""
deduplicate_crashes.py  — Student A (Day 11)
---------------------------------------------
Analyzes dynamic crash artifacts from AFL++, ASan, and KLEE:
1. Extracts crash stack traces, fault signals, and error descriptions.
2. Computes SHA-256 unique crash hashes.
3. Maps crashes to precise CWEs:
   - heap-buffer-overflow / stack-buffer-overflow -> CWE-787 / CWE-120
   - global-buffer-overflow / out-of-bounds-read  -> CWE-125
   - null-dereference / segfault                 -> CWE-476
   - use-after-free                              -> CWE-416
   - signed-integer-overflow                     -> CWE-190
4. Deduplicates crashes and updates crash counts.
"""

import os
import sys
import sqlite3
import glob
import re
import hashlib
import json
import argparse

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
DB_PATH  = os.path.join(BASE_DIR, 'corpus.db')
RESULTS_DIR = os.path.join(BASE_DIR, 'results')
AFL_TARGETS_DIR = os.path.join(RESULTS_DIR, 'afl_targets')

def compute_crash_signature(crash_content: str) -> tuple[str, str]:
    """Extract crash signature and determine CWE."""
    cwe = "CWE-119"  # General memory corruption default
    
    content_lower = crash_content.lower()
    if "stack-buffer-overflow" in content_lower or "stack overflow" in content_lower:
        cwe = "CWE-121"
    elif "heap-buffer-overflow" in content_lower or "heap overflow" in content_lower:
        cwe = "CWE-122"
    elif "global-buffer-overflow" in content_lower or "out-of-bounds" in content_lower:
        cwe = "CWE-125"
    elif "null-dereference" in content_lower or "null pointer" in content_lower or "address 0x0000" in content_lower:
        cwe = "CWE-476"
    elif "use-after-free" in content_lower or "heap-use-after-free" in content_lower:
        cwe = "CWE-416"
    elif "double-free" in content_lower:
        cwe = "CWE-415"
    elif "integer overflow" in content_lower or "signed integer" in content_lower:
        cwe = "CWE-190"
    elif "segfault" in content_lower or "signal 11" in content_lower or "sigsegv" in content_lower:
        cwe = "CWE-476"
    elif "sigabrt" in content_lower or "abort" in content_lower:
        cwe = "CWE-617"

    # Normalize error trace for hash deduplication
    match_frame = re.search(r'#0\s+0x[0-9a-fA-F]+\s+in\s+([^\n]+)', crash_content)
    frame_text = match_frame.group(1).strip() if match_frame else cwe
    sig_hash = hashlib.sha256(f"{cwe}:{frame_text}".encode('utf-8')).hexdigest()[:16]
    return sig_hash, cwe

def deduplicate_all_crashes(limit=None):
    print("=" * 70)
    print("DAY 11: DEDUPLICATING CRASHES & COMPUTING CRASH HASHES")
    print("=" * 70)
    
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    
    query = """
    SELECT f.program_id
    FROM filtered_files f
    WHERE f.language = 'C' AND f.stage1 = 'PASSED'
    ORDER BY f.id ASC
    """
    if limit:
        query += f" LIMIT {limit}"
        
    cur.execute(query)
    pids = [r[0] for r in cur.fetchall()]
    print(f"Evaluating crash artifacts for {len(pids)} programs...")
    
    total_raw_crashes = 0
    unique_crashes_map = {}
    crashed_summary = {}

    for pid in pids:
        target_dir = os.path.join(AFL_TARGETS_DIR, pid)
        crashes_dir = os.path.join(target_dir, "crashes")
        
        crash_files = glob.glob(os.path.join(crashes_dir, "crash_*.txt"))
        total_raw_crashes += len(crash_files)
        
        hashes = set()
        cwe_counts = {}
        
        for cf in crash_files:
            try:
                with open(cf, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                sig_hash, cwe = compute_crash_signature(content)
                hashes.add(sig_hash)
                cwe_counts[cwe] = cwe_counts.get(cwe, 0) + 1
            except Exception:
                pass
                
        # Also check if KLEE direct crash was recorded
        klee_dir = os.path.join(RESULTS_DIR, 'klee_out', pid)
        if os.path.exists(klee_dir):
            err_files = glob.glob(os.path.join(klee_dir, "*.err"))
            for ef in err_files:
                sig_hash = hashlib.sha256(os.path.basename(ef).encode('utf-8')).hexdigest()[:16]
                hashes.add(sig_hash)
                if ".ptr.err" in ef:
                    cwe_counts["CWE-476"] = cwe_counts.get("CWE-476", 0) + 1
                elif ".assert.err" in ef:
                    cwe_counts["CWE-617"] = cwe_counts.get("CWE-617", 0) + 1
                elif ".overflow.err" in ef:
                    cwe_counts["CWE-190"] = cwe_counts.get("CWE-190", 0) + 1

        if hashes:
            top_cwe = sorted(cwe_counts.items(), key=lambda x: x[1], reverse=True)[0][0] if cwe_counts else "CWE-119"
            crashed_summary[pid] = {
                "crashed": 1,
                "confirmed_count": len(hashes),
                "unique_hashes": list(hashes),
                "dynamic_cwe": top_cwe
            }
            unique_crashes_map[pid] = top_cwe

    print("\n" + "=" * 70)
    print("CRASH DEDUPLICATION SUMMARY:")
    print(f"  Total Raw Crash Files:     {total_raw_crashes}")
    print(f"  Unique Programs Crashed:   {len(crashed_summary)}")
    print(f"  Total Unique Crash Hashes: {sum(len(v['unique_hashes']) for v in crashed_summary.values())}")
    print("=" * 70)
    
    conn.close()
    return crashed_summary

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=None)
    args = parser.parse_args()
    deduplicate_all_crashes(args.limit)
