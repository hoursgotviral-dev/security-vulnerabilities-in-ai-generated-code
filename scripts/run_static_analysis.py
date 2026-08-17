import sqlite3
import subprocess
import os
import shutil

DB_PATH = '../corpus.db'
OUT_DIR = '../results/static_raw'
os.makedirs(OUT_DIR, exist_ok=True)

TOOL_AVAILABLE = {
    'bandit': shutil.which('bandit') is not None,
    'flawfinder': shutil.which('flawfinder') is not None,
    'semgrep': shutil.which('semgrep') is not None,
}
print("Tool availability:", TOOL_AVAILABLE)

def run_analysis():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""SELECT r.program_id, r.content, r.language
                       FROM raw_files r
                       JOIN filtered_files f ON r.program_id = f.program_id
                       WHERE f.stage1 = 'PASSED'""")
    files = cursor.fetchall()
    print(f"Starting static analysis on {len(files)} filtered files...")

    if not files:
        print("WARNING: no rows in filtered_files with stage1='PASSED'. "
              "Run verify_comment_location.py + filter_stage1.py first.")
        return

    for pid, content, lang in files:
        ext = '.py' if lang.lower() == 'python' else '.c'
        tmp_path = f'/tmp/static_scan_{pid}{ext}'
        with open(tmp_path, 'w') as f:
            f.write(content or '')

        if lang.lower() == 'python' and TOOL_AVAILABLE['bandit']:
            result = subprocess.run(['bandit', '-f', 'json', tmp_path],
                                     capture_output=True, text=True)
            with open(f'{OUT_DIR}/bandit_{pid}.json', 'w') as f:
                f.write(result.stdout)

        if lang.lower() == 'python' and TOOL_AVAILABLE['semgrep']:
            subprocess.run(['semgrep', '--config=p/security-audit',
                             '--json', '--output', f'{OUT_DIR}/semgrep_{pid}.json', tmp_path],
                            capture_output=True, text=True)

        if lang.lower() == 'c' and TOOL_AVAILABLE['flawfinder']:
            result = subprocess.run(['flawfinder', '--csv', tmp_path],
                                     capture_output=True, text=True)
            with open(f'{OUT_DIR}/flawfinder_{pid}.csv', 'w') as f:
                f.write(result.stdout)

        os.remove(tmp_path)
        if pid % 20 == 0:
            print(f"  ...scanned program_id {pid}")

    print("Static analysis complete. Raw output in results/static_raw/")

if __name__ == "__main__":
    run_analysis()
