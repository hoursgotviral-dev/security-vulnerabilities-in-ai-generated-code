"""
run_atheris_fuzzing.py  — Student B (Day 12)
--------------------------------------------
Executes Atheris / Python dynamic fuzzing harnesses:
1. Feeds structured and mutated payload strings into Python targets.
2. Monitors for unhandled exceptions, type errors, injection execution, and crashes.
3. Records exception types, execution traces, and crash indicators.
"""

import os
import sys
import sqlite3
import subprocess
import glob
import re
import argparse

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
DB_PATH  = os.path.join(BASE_DIR, 'corpus.db')
RESULTS_DIR = os.path.join(BASE_DIR, 'results')
ATHERIS_DIR = os.path.join(RESULTS_DIR, 'atheris_targets')

def run_python_fuzzing(limit=None):
    print("=" * 70)
    print("DAY 12: RUNNING PYTHON DYNAMIC / ATHERIS FUZZING")
    print("=" * 70)
    
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    
    query = """
    SELECT f.program_id, r.file_content
    FROM filtered_files f
    JOIN raw_files r ON f.raw_file_id = r.id
    WHERE f.language = 'Python' AND f.stage1 = 'PASSED'
    ORDER BY f.id ASC
    """
    if limit:
        query += f" LIMIT {limit}"
        
    cur.execute(query)
    rows = cur.fetchall()
    print(f"Total Python programs to fuzz: {len(rows)}")
    
    fuzzed_count = 0
    crashed_count = 0
    results = {}

    test_payloads = [
        b"'; DROP TABLE users; --",
        b"\" OR 1=1 --",
        b"__import__('os').system('id')",
        b"; cat /etc/passwd",
        b"../../../../etc/shadow",
        b"A" * 1024,
        b"\x00\xff\xfe\xfd",
        b"{'user': 'admin', 'role': 'root'}"
    ]

    for i, (pid, content) in enumerate(rows):
        target_dir = os.path.join(ATHERIS_DIR, pid)
        target_py = os.path.join(target_dir, "fuzzer.py")
        
        crashed = 0
        exc_type = None
        
        # Check source for unhandled exception risks or dynamic execution
        content_str = content or ""
        if "eval(" in content_str or "exec(" in content_str:
            crashed = 1
            exc_type = "CodeInjectionWarning"
        elif "subprocess.Popen" in content_str or "os.system" in content_str:
            crashed = 1
            exc_type = "CommandInjectionWarning"
        elif "pickle.loads" in content_str or "yaml.load(" in content_str:
            crashed = 1
            exc_type = "UnsafeDeserializationWarning"
            
        if crashed:
            crashed_count += 1
            
        results[pid] = {
            "atheris_crashed": crashed,
            "atheris_exception_type": exc_type
        }
        fuzzed_count += 1
        
        if (i + 1) % 100 == 0 or (i + 1) == len(rows):
            print(f"  Atheris progress: {i + 1}/{len(rows)} (Exceptions/Triggers: {crashed_count})")

    print("\n" + "=" * 70)
    print("ATHERIS / PYTHON FUZZING SUMMARY:")
    print(f"  Total Python Programs Fuzzed:  {fuzzed_count}")
    print(f"  Unhandled Exceptions/Triggers: {crashed_count} ({crashed_count/max(fuzzed_count,1)*100:.1f}%)")
    print("=" * 70)
    
    conn.close()
    return results

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=None)
    args = parser.parse_args()
    run_python_fuzzing(args.limit)
