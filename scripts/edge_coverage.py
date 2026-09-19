"""
edge_coverage.py  — Dynamic edge/line coverage (REAL measurement version)

Replaces the earlier version that COMPUTED a plausible-looking coverage number
from a formula (45.0 + ktests*8.5 + branch_points*2.0). That was fabricated.

This version measures coverage for real:
  - Python: runs the program under coverage.py and reads the actual
    percentage of executable lines that ran.
  - C: uses afl-showmap on an instrumented binary to count edges actually
    exercised, when the binary and afl-showmap are available.

Honesty guarantees:
  - If the required tool is not installed, or a program cannot be measured,
    the coverage is stored as NULL and marked with a status. NO formula, no
    guess, no fallback number is ever written.
  - Only real measured percentages go into edge_coverage_pct.

Requires: `pip install coverage` for Python; afl-showmap on PATH for C.
"""
import os, sys, sqlite3, subprocess, tempfile, argparse, shutil, glob, re

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
DB_PATH  = os.path.join(BASE_DIR, 'corpus.db')
RESULTS_DIR = os.path.join(BASE_DIR, 'results')

def _try_import_coverage():
    try:
        import coverage  # noqa
        return True
    except Exception:
        return False

COVERAGE_AVAILABLE = shutil.which('coverage') is not None or _try_import_coverage()
SHOWMAP = shutil.which('afl-showmap')

def measure_python(code, timeout_sec=15):
    """Return (pct:float|None, status:str). pct is real line coverage or None."""
    try:
        import coverage
    except Exception:
        return None, 'COVERAGE_NOT_INSTALLED'
    d = tempfile.mkdtemp()
    path = os.path.join(d, 'prog.py')
    with open(path, 'w') as f:
        f.write(code)
    try:
        cov = coverage.Coverage(data_file=os.path.join(d, '.coverage'))
        cov.start()
        # execute the program in-process guardedly
        import runpy
        try:
            runpy.run_path(path)
        except SystemExit:
            pass
        except Exception:
            # program raised — coverage up to the raise still counts, keep going
            pass
        cov.stop()
        # measure
        total = covered = 0
        ana = cov.analysis2(path)  # (filename, statements, excluded, missing, missing_formatted)
        statements = ana[1]; missing = ana[3]
        total = len(statements)
        covered = total - len(missing)
        if total == 0:
            return None, 'NO_STATEMENTS'
        return round(100.0 * covered / total, 1), 'MEASURED'
    except Exception as e:
        return None, f'ERROR:{type(e).__name__}'
    finally:
        shutil.rmtree(d, ignore_errors=True)

def measure_c(pid):
    """Return (pct:float|None, status:str) using afl-showmap on the built binary."""
    if not SHOWMAP:
        return None, 'AFL_SHOWMAP_NOT_FOUND'
    binp = os.path.join(RESULTS_DIR, 'afl_targets', pid, 'target.bin')
    queue = os.path.join(RESULTS_DIR, 'afl_out', pid, 'queue')
    if not os.path.exists(binp):
        return None, 'NO_BINARY'
    inputs = glob.glob(os.path.join(queue, '*')) if os.path.exists(queue) else []
    if not inputs:
        return None, 'NO_INPUTS'
    total_edges = set()
    for inp in inputs[:200]:
        try:
            out = tempfile.NamedTemporaryFile(delete=False).name
            subprocess.run([SHOWMAP, '-o', out, '-q', '--', binp, inp],
                           capture_output=True, timeout=10)
            with open(out) as f:
                for line in f:
                    eid = line.split(':')[0].strip()
                    if eid:
                        total_edges.add(eid)
            os.unlink(out)
        except Exception:
            continue
    if not total_edges:
        return None, 'NO_EDGES'
    # afl-showmap gives edges hit; normalise against the map size (65536 is the AFL default)
    pct = round(100.0 * len(total_edges) / 65536.0, 3)
    return pct, 'MEASURED'

def run(limit=None):
    if not COVERAGE_AVAILABLE and not SHOWMAP:
        print("Neither coverage.py nor afl-showmap is available.")
        print("Install with: pip install coverage   (and build AFL for afl-showmap)")
        print("Refusing to write fabricated coverage. Exiting.")
        sys.exit(1)

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    q = """
        SELECT f.program_id, f.language, r.file_content
        FROM filtered_files f JOIN raw_files r ON f.raw_file_id=r.id
        WHERE f.stage1='PASSED' ORDER BY f.id ASC
    """
    if limit:
        q += f" LIMIT {int(limit)}"
    rows = cur.execute(q).fetchall()
    print(f"Measuring real coverage for {len(rows)} programs...")

    cur.execute("CREATE TABLE IF NOT EXISTS dynamic_coverage (program_id TEXT, language TEXT, edge_coverage_pct REAL, status TEXT)")

    measured = skipped = 0
    for i, (pid, lang, content) in enumerate(rows, 1):
        if lang == 'Python' and content:
            pct, status = measure_python(content)
        elif lang == 'C':
            pct, status = measure_c(pid)
        else:
            pct, status = None, 'UNSUPPORTED_LANG'
        cur.execute("INSERT INTO dynamic_coverage VALUES (?,?,?,?)", (pid, lang, pct, status))
        if pct is not None: measured += 1
        else: skipped += 1
        if i % 100 == 0:
            conn.commit(); print(f"  {i}/{len(rows)}  measured: {measured}")
    conn.commit(); conn.close()
    print("\n=== REAL coverage measurement complete ===")
    print(f"  measured (real pct): {measured}")
    print(f"  skipped (NULL, tool/binary missing): {skipped}")
    print("Only 'measured' rows have real coverage. Skipped rows are NULL, never a formula.")

if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--limit', type=int, default=None)
    run(ap.parse_args().limit)