import sqlite3
import json
import sys
import os

def load_cwe_corrections():
    corrections_path = 'scripts/bandit_cwe_corrections.json'
    if not os.path.exists(corrections_path):
        print(f"Warning: {corrections_path} not found. No corrections will be applied.")
        return {}
    with open(corrections_path) as f:
        data = json.load(f)
    # Remove the _note key
    return {k: v for k, v in data.items() if k != '_note'}

def get_program_id_for_file(conn, file_path):
    c = conn.cursor()
    row = c.execute(
        'SELECT program_id FROM filtered_files WHERE file_path = ?',
        (file_path,)
    ).fetchone()
    if row:
        return row[0]
    basename = os.path.basename(file_path)
    row = c.execute(
        'SELECT program_id FROM filtered_files WHERE file_path LIKE ?',
        (f'%{basename}%',)
    ).fetchone()
    if row:
        return row[0]
    return None

def ingest_bandit(bandit_json_path, conn):
    if not os.path.exists(bandit_json_path):
        print(f"Error: File not found: {bandit_json_path}")
        return 0

    with open(bandit_json_path) as f:
        data = json.load(f)

    corrections = load_cwe_corrections()
    c = conn.cursor()

    inserted   = 0
    updated    = 0
    skipped    = 0
    corrected  = 0

    results = data.get('results', [])

    for result in results:
        file_path   = result.get('filename', '')
        line_number = result.get('line_number', 0)
        rule_id     = result.get('test_id', '')
        rule_name   = result.get('test_name', '')
        severity    = result.get('issue_severity', 'LOW').lower()
        message     = result.get('issue_text', '')

        # Get CWE from Bandit output
        # Bandit stores CWE as a dict: {"id": 89, "link": "..."}
        cwe_raw = result.get('issue_cwe', {})
        if isinstance(cwe_raw, dict):
            cwe_id = cwe_raw.get('id', '')
            bandit_cwe = f'CWE-{cwe_id}' if cwe_id else None
        else:
            bandit_cwe = str(cwe_raw) if cwe_raw else None

        # Apply correction if one exists
        cwe_corrected_flag = 0
        final_cwe = bandit_cwe

        if rule_id in corrections:
            correction = corrections[rule_id]
            correct_cwe = correction.get('correct_cwe')
            was_corrected = correction.get('corrected', False)

            if was_corrected and correct_cwe and correct_cwe != bandit_cwe:
                final_cwe = correct_cwe
                cwe_corrected_flag = 1
                corrected += 1

        if not file_path:
            skipped += 1
            continue

        program_id = get_program_id_for_file(conn, file_path)

        # Deduplication check
        existing = c.execute('''
            SELECT id, tool_count FROM static_results
            WHERE file_path = ?
            AND line_number = ?
            AND cwe = ?
        ''', (file_path, line_number, final_cwe)).fetchone()

        if existing and final_cwe:
            c.execute('''
                UPDATE static_results
                SET tool_count = tool_count + 1
                WHERE id = ?
            ''', (existing[0],))
            updated += 1
        else:
            c.execute('''
                INSERT INTO static_results
                (program_id, file_path, tool, line_number,
                 rule_id, cwe, cwe_corrected, severity,
                 message, tool_count, static_flagged)
                VALUES (?, ?, 'bandit', ?, ?, ?, ?, ?, ?, 1, 1)
            ''', (program_id, file_path, line_number,
                  rule_id, final_cwe, cwe_corrected_flag,
                  severity, message))
            inserted += 1

    conn.commit()

    print(f"  bandit : {inserted} new findings, "
          f"{updated} duplicates merged, "
          f"{skipped} skipped, "
          f"{corrected} CWEs corrected")
    return inserted

def run_ingest(bandit_json_path):
    conn = sqlite3.connect('corpus.db')
    print(f"\nIngesting Bandit results from: {bandit_json_path}")
    count = ingest_bandit(bandit_json_path, conn)
    print(f"  Total static_results rows: "
          f"{conn.execute('SELECT COUNT(*) FROM static_results').fetchone()[0]}")

    # Show correction summary
    corrected_count = conn.execute(
        'SELECT COUNT(*) FROM static_results '
        'WHERE tool = "bandit" AND cwe_corrected = 1'
    ).fetchone()[0]
    total_bandit = conn.execute(
        'SELECT COUNT(*) FROM static_results WHERE tool = "bandit"'
    ).fetchone()[0]

    if total_bandit > 0:
        print(f"  Bandit CWE corrections applied: "
              f"{corrected_count} of {total_bandit} "
              f"({corrected_count/total_bandit*100:.1f}%)")

    conn.close()
    return count

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python3 scripts/ingest_bandit.py <bandit_json_file>")
        print("")
        print("Example:")
        print("  python3 scripts/ingest_bandit.py results/bandit_results.json")
        sys.exit(1)

    run_ingest(sys.argv[1])
