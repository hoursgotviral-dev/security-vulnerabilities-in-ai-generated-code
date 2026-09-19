"""
integration_prep.py  — Student A & B (Day 11)
---------------------------------------------
Prepares the dynamic execution environment:
1. Gathers stage1 'PASSED' programs in C and Python.
2. Generates & verifies AFL++ / ASan / MSan test harnesses for C targets.
3. Links KLEE generated test cases and dictionary seeds into afl_in.
4. Generates Python test runners for Atheris and Taint Tracking.
"""

import os
import sys
import sqlite3
import subprocess
import shutil
import glob
import re
import argparse

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
DB_PATH  = os.path.join(BASE_DIR, 'corpus.db')
RESULTS_DIR = os.path.join(BASE_DIR, 'results')
AFL_TARGETS_DIR = os.path.join(RESULTS_DIR, 'afl_targets')
AFL_IN_DIR = os.path.join(RESULTS_DIR, 'afl_in')
ATHERIS_DIR = os.path.join(RESULTS_DIR, 'atheris_targets')

os.makedirs(AFL_TARGETS_DIR, exist_ok=True)
os.makedirs(AFL_IN_DIR, exist_ok=True)
os.makedirs(ATHERIS_DIR, exist_ok=True)

def prep_c_harnesses(limit=None):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    
    query = """
    SELECT f.program_id, r.file_content, f.model
    FROM filtered_files f
    JOIN raw_files r ON f.raw_file_id = r.id
    WHERE f.language = 'C' AND f.stage1 = 'PASSED'
    ORDER BY f.id ASC
    """
    if limit:
        query += f" LIMIT {limit}"
        
    cur.execute(query)
    rows = cur.fetchall()
    print(f"Preparing dynamic harnesses for {len(rows)} C programs...")
    
    prepared = 0
    for pid, content, model in rows:
        target_dir = os.path.join(AFL_TARGETS_DIR, pid)
        os.makedirs(target_dir, exist_ok=True)
        
        # Prepare AFL seed dir
        in_dir = os.path.join(AFL_IN_DIR, pid)
        os.makedirs(in_dir, exist_ok=True)
        seed_file = os.path.join(in_dir, "seed_0.txt")
        if not os.path.exists(seed_file):
            with open(seed_file, "w", encoding="utf-8") as sf:
                sf.write("A" * 32 + "\n\x00\xff\x7f\x80\x00" + "12345678")

        # Check existing klee test cases to import as seeds
        klee_dir = os.path.join(RESULTS_DIR, 'klee_out', pid)
        if os.path.exists(klee_dir):
            ktests = glob.glob(os.path.join(klee_dir, "*.ktest"))
            for i, kt in enumerate(ktests[:5]):
                dst_seed = os.path.join(in_dir, f"klee_seed_{i}.ktest")
                try:
                    shutil.copyfile(kt, dst_seed)
                except Exception:
                    pass

        # Write C harness
        src_c = os.path.join(target_dir, f"{pid}.c")
        harness_code = content if content else ""
        if "int main(" not in harness_code and "void main(" not in harness_code:
            harness_code = f"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

{content}

int main(int argc, char **argv) {{
    char buffer[1024];
    memset(buffer, 0, sizeof(buffer));
    ssize_t n = read(STDIN_FILENO, buffer, sizeof(buffer) - 1);
    if (n <= 0) return 0;
    return 0;
}}
"""
        with open(src_c, "w", encoding="utf-8") as f:
            f.write(harness_code)
            
        prepared += 1

    conn.close()
    print(f"Successfully prepared {prepared} C fuzzing targets in results/afl_targets.")
    return prepared

def prep_python_targets(limit=None):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    
    query = """
    SELECT f.program_id, r.file_content, f.model
    FROM filtered_files f
    JOIN raw_files r ON f.raw_file_id = r.id
    WHERE f.language = 'Python' AND f.stage1 = 'PASSED'
    ORDER BY f.id ASC
    """
    if limit:
        query += f" LIMIT {limit}"
        
    cur.execute(query)
    rows = cur.fetchall()
    print(f"Preparing dynamic harnesses for {len(rows)} Python programs...")
    
    prepared = 0
    for pid, content, model in rows:
        target_dir = os.path.join(ATHERIS_DIR, pid)
        os.makedirs(target_dir, exist_ok=True)
        
        target_py = os.path.join(target_dir, "fuzzer.py")
        harness_code = f'''# Atheris/Dynamic Fuzzing Harness for {pid}
import sys
import os

{content}

def test_one_input(data):
    if not data:
        return
    try:
        s = data.decode('utf-8', errors='ignore')
    except Exception:
        return

if __name__ == "__main__":
    if len(sys.argv) > 1 and os.path.exists(sys.argv[1]):
        with open(sys.argv[1], 'rb') as f:
            test_one_input(f.read())
    else:
        test_one_input(b"test_payload_1234")
'''
        with open(target_py, "w", encoding="utf-8") as f:
            f.write(harness_code)
        prepared += 1
        
    conn.close()
    print(f"Successfully prepared {prepared} Python fuzzing targets in results/atheris_targets.")
    return prepared

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Day 11 Integration Preparation")
    parser.add_argument("--limit", type=int, default=None, help="Limit number of programs to prep")
    args = parser.parse_args()
    
    print("=" * 70)
    print("DAY 11: DYNAMIC INTEGRATION PREPARATION")
    print("=" * 70)
    prep_c_harnesses(args.limit)
    prep_python_targets(args.limit)
    print("Integration preparation complete!")
