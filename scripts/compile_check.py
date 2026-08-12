import sqlite3
import subprocess
import tempfile
import os
import shutil

COMMON_HEADERS = [
    '#include <stdio.h>',
    '#include <stdlib.h>',
    '#include <string.h>',
    '#include <stdint.h>',
    '#include <stdbool.h>',
]

# Detect whether node is available once, at startup, so we can check JS syntax.
NODE_AVAILABLE = shutil.which('node') is not None


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
        return ('SYNTAX_OK' if result.returncode == 0 else 'SYNTAX_FAIL'), result.stderr
    finally:
        os.unlink(tmp_path)


def try_check_javascript(content):
    """
    JavaScript is not compiled. If node is available, use `node --check` to
    confirm the file parses (a syntax check, not execution). If node is not
    installed, mark JS_SKIP so these files are still counted as usable for
    static analysis (ESLint) rather than wrongly failed.
    """
    if not NODE_AVAILABLE:
        return 'JS_SKIP', ''
    with tempfile.NamedTemporaryFile(suffix='.js', mode='w', delete=False) as f:
        f.write(content)
        tmp_path = f.name
    try:
        result = subprocess.run(
            ['node', '--check', tmp_path],
            capture_output=True, text=True, timeout=10
        )
        return ('SYNTAX_OK' if result.returncode == 0 else 'SYNTAX_FAIL'), result.stderr
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
        elif language == 'JavaScript':
            status, _ = try_check_javascript(content)
        elif language == 'C':
            ok, stderr = try_compile_c(content)
            if ok:
                status = 'COMPILED'
            else:
                status, _, _ = try_repair_and_compile(content)
        else:
            # Unknown language: don't fail it on a C compiler. Flag for review.
            status = 'LANG_SKIP'

        c.execute(
            'UPDATE filtered_files SET compile_status = ? WHERE program_id = ?',
            (status, program_id)
        )
        results[status] = results.get(status, 0) + 1

    conn.commit()
    conn.close()

    print('Compile results:')
    for status, count in sorted(results.items()):
        print(f'  {status}: {count}')
    if not results:
        print('  No files to check yet (waiting for Stage 1 data)')
    if not NODE_AVAILABLE:
        print('\nNote: node not found, so JavaScript files were marked JS_SKIP '
              '(counted as usable for static analysis). Install Node.js to enable '
              'JS syntax checking.')


if __name__ == '__main__':
    run_compile_checks()