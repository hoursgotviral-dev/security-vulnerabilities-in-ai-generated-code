import sqlite3
import subprocess
import tempfile
import os

COMMON_HEADERS = [
    '#include <stdio.h>',
    '#include <stdlib.h>',
    '#include <string.h>',
    '#include <stdint.h>',
    '#include <stdbool.h>',
]

def try_compile_c(content):
    with tempfile.NamedTemporaryFile(suffix='.c', mode='w', delete=False) as f:
        f.write(content)
        tmp_path = f.name
    try:
        result = subprocess.run(
            ['gcc', '-Wall', '-Wno-unused', '-fsyntax-only', tmp_path],
            capture_output=True, text=True, timeout=30
        )
        return result.returncode == 0, result.stderr
    finally:
        os.unlink(tmp_path)

def try_repair_and_compile(content):
    header_block = '\n'.join(COMMON_HEADERS) + '\n\n'
    repaired = header_block + content
    success, stderr = try_compile_c(repaired)
    if success:
        return 'REPAIR_COMPILED', repaired, stderr
    return 'COMPILE_FAIL', content, stderr

def try_compile_python(content):
    with tempfile.NamedTemporaryFile(suffix='.py', mode='w', delete=False) as f:
        f.write(content)
        tmp_path = f.name
    try:
        result = subprocess.run(
            ['python3', '-m', 'py_compile', tmp_path],
            capture_output=True, text=True, timeout=10
        )
        return 'SYNTAX_OK' if result.returncode == 0 else 'SYNTAX_FAIL', result.stderr
    finally:
        os.unlink(tmp_path)

def run_compile_checks():
    conn = sqlite3.connect('corpus.db')
    c = conn.cursor()

    rows = c.execute(
        'SELECT ff.program_id, ff.language, r.file_content '
        'FROM filtered_files ff '
        'JOIN raw_files r ON ff.raw_file_id = r.id '
        'WHERE ff.stage1 = "PASSED" AND ff.compile_status IS NULL'
    ).fetchall()

    print(f'Running compile checks on {len(rows)} files...')
    results = {}

    for program_id, language, content in rows:
        if content is None:
            status = 'COMPILE_FAIL'
        elif language == 'Python':
            status, _ = try_compile_python(content)
        else:
            ok, stderr = try_compile_c(content)
            if ok:
                status = 'COMPILED'
            else:
                status, _, _ = try_repair_and_compile(content)

        c.execute(
            'UPDATE filtered_files SET compile_status = ? WHERE program_id = ?',
            (status, program_id)
        )
        results[status] = results.get(status, 0) + 1

    conn.commit()
    conn.close()

    print('Compile results:')
    for status, count in results.items():
        print(f'  {status}: {count}')
    if not results:
        print('  No files to check yet (waiting for Stage 1 data)')

if __name__ == '__main__':
    run_compile_checks()
