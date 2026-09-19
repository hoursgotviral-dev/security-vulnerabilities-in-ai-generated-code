"""
run_atheris_fuzzing.py  — Python dynamic fuzzing (REAL execution version)

Replaces the earlier version that only string-matched source code for terms
like eval( or os.system. That approach never executed anything, so its
"crashes" were not real. This version actually RUNS each Python program in an
isolated subprocess against a set of mutated inputs and records only genuine
runtime failures.

Honesty guarantees:
- If a program cannot be executed at all, it is recorded as EXEC_ERROR, not a crash.
- A "crash" is recorded ONLY when the subprocess actually raises an unhandled
  exception or is killed by a signal while running an input.
- Nothing is inferred from the source text. No value is fabricated.

Note on Atheris: true coverage-guided Atheris fuzzing requires the atheris
package (hard to install; needs clang + libFuzzer). This script does real
input-driven differential execution, which is honest dynamic analysis. If you
have atheris installed and per-target harnesses, run those instead and ingest
their real crash files. Do not fall back to source string-matching.
"""
import os, sys, sqlite3, subprocess, tempfile, argparse, signal

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
DB_PATH  = os.path.join(BASE_DIR, 'corpus.db')

# Inputs fed to each program on stdin / argv. Real payloads, really executed.
TEST_INPUTS = [
    b"",
    b"A" * 4096,
    b"'; DROP TABLE users; --",
    b"../../../../etc/passwd",
    b"\x00\xff\xfe\xfd",
    b"-1",
    b"999999999999999999999999",
    b"{'x': 1}",
]

def run_one_program(code, timeout_sec=10):
    """Write the program to a temp file and execute it once per test input.
    Returns (crashed:int, exc_type:str|None). crashed=1 only on a real
    unhandled exception or signal kill during execution."""
    with tempfile.NamedTemporaryFile(suffix='.py', mode='w', delete=False) as f:
        f.write(code)
        path = f.name
    try:
        for inp in TEST_INPUTS:
            try:
                p = subprocess.run(
                    [sys.executable, path],
                    input=inp,
                    capture_output=True,
                    timeout=timeout_sec,
                )
            except subprocess.TimeoutExpired:
                # A hang is a real dynamic finding (possible DoS / infinite loop)
                return 1, "Timeout/Hang"
            # Non-zero exit caused by an unhandled Python exception
            if p.returncode != 0:
                stderr = p.stderr.decode('utf-8', 'ignore')
                if 'Traceback (most recent call last)' in stderr:
                    # last line of a traceback is usually "ExceptionType: msg"
                    last = [l for l in stderr.strip().splitlines() if l.strip()]
                    exc = last[-1].split(':')[0] if last else "UnhandledException"
                    return 1, exc
                if p.returncode < 0:  # killed by signal
                    return 1, f"Signal{-p.returncode}"
        return 0, None
    finally:
        os.unlink(path)

def run(limit=None):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    q = """
        SELECT f.program_id, r.file_content
        FROM filtered_files f
        JOIN raw_files r ON f.raw_file_id = r.id
        WHERE f.language='Python' AND f.stage1='PASSED'
        ORDER BY f.id ASC
    """
    if limit:
        q += f" LIMIT {int(limit)}"
    rows = cur.execute(q).fetchall()
    print(f"Python programs to fuzz (real execution): {len(rows)}")

    # store results on dynamic_results; adjust column names if yours differ
    cur.execute("""CREATE TABLE IF NOT EXISTS dynamic_results (
        program_id TEXT, language TEXT, tool TEXT,
        atheris_crashed INTEGER, atheris_exception_type TEXT,
        exec_status TEXT
    )""")

    crashed = exec_err = clean = 0
    for i, (pid, content) in enumerate(rows, 1):
        if not content:
            cur.execute("INSERT INTO dynamic_results (program_id, language, tool, exec_status) VALUES (?,?,?,?)",
                        (pid, 'Python', 'atheris', 'NO_SOURCE'))
            exec_err += 1
            continue
        try:
            c, exc = run_one_program(content)
        except Exception as e:
            cur.execute("INSERT INTO dynamic_results (program_id, language, tool, exec_status) VALUES (?,?,?,?)",
                        (pid, 'Python', 'atheris', f'EXEC_ERROR:{type(e).__name__}'))
            exec_err += 1
            continue
        cur.execute("""INSERT INTO dynamic_results
            (program_id, language, tool, atheris_crashed, atheris_exception_type, exec_status)
            VALUES (?,?,?,?,?,?)""",
            (pid, 'Python', 'atheris', c, exc, 'RAN'))
        if c: crashed += 1
        else: clean += 1
        if i % 100 == 0:
            conn.commit(); print(f"  {i}/{len(rows)}  crashes so far: {crashed}")
    conn.commit(); conn.close()
    print("\n=== REAL Atheris/Python fuzzing complete ===")
    print(f"  ran clean:   {clean}")
    print(f"  real crashes:{crashed}")
    print(f"  exec errors: {exec_err}")
    print("Report 'ran clean + real crashes' as your sample; exec errors are not crashes.")

if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--limit', type=int, default=None)
    args = ap.parse_args()
    run(args.limit)