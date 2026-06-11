import sqlite3
import csv
import sys
import os

# DeVAIC rule ID to CWE mapping
# Based on DeVAIC's published rule table (Python-specific rules)
DEVAIC_CWE_MAP = {
    'sql-injection':              'CWE-89',
    'command-injection':          'CWE-78',
    'path-traversal':             'CWE-22',
    'xss':                        'CWE-79',
    'hardcoded-password':         'CWE-259',
    'hardcoded-secret':           'CWE-798',
    'weak-crypto':                'CWE-327',
    'insecure-deserialization':   'CWE-502',
    'open-redirect':              'CWE-601',
    'ssrf':                       'CWE-918',
    'xxe':                        'CWE-611',
    'insecure-random':            'CWE-338',
    'eval-injection':             'CWE-95',
    'ldap-injection':             'CWE-90',
    'xpath-injection':            'CWE-643',
    'unvalidated-redirect':       'CWE-601',
    'trust-boundary-violation':   'CWE-501',
    'sensitive-data-exposure':    'CWE-200',
    'insecure-temp-file':         'CWE-377',
    'subprocess-shell':           'CWE-78',
}

def get_cwe_for_rule(rule_id):
    """
    Map a DeVAIC rule ID to a CWE.
    Tries exact match first, then partial match.
    """
    rule_lower = rule_id.lower().strip()

    # Exact match
    if rule_lower in DEVAIC_CWE_MAP:
        return DEVAIC_CWE_MAP[rule_lower]

    # Partial match — rule ID may contain extra info
    for key, cwe in DEVAIC_CWE_MAP.items():
        if key in rule_lower or rule_lower in key:
            return cwe

    # If the rule ID itself looks like a CWE
    if 'cwe' in rule_lower:
        parts = rule_lower.replace('-', ' ').split()
        for i, part in enumerate(parts):
            if part == 'cwe' and i + 1 < len(parts):
                return f'CWE-{parts[i+1]}'

    return None

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

def ingest_devaic(csv_path, conn):
    if not os.path.exists(csv_path):
        print(f"Error: File not found: {csv_path}")
        return 0

    c = conn.cursor()
    inserted  = 0
    updated   = 0
    skipped   = 0
    no_cwe    = 0

    with open(csv_path, newline='', encoding='utf-8') as f:
        # DeVAIC CSV columns may vary — detect them from header
        reader = csv.DictReader(f)
        headers = reader.fieldnames or []

        # Normalise header names to lowercase
        # DeVAIC typically outputs: filename, line, rule, severity, message
        for row in reader:
            row_lower = {k.lower().strip(): v for k, v in row.items()}

            # Try to extract fields with flexible column name matching
            file_path = (
                row_lower.get('filename') or
                row_lower.get('file') or
                row_lower.get('path') or ''
            ).strip()

            line_str = (
                row_lower.get('line') or
                row_lower.get('line_number') or
                row_lower.get('lineno') or '0'
            ).strip()

            rule_id = (
                row_lower.get('rule') or
                row_lower.get('rule_id') or
                row_lower.get('check') or ''
            ).strip()

            severity = (
                row_lower.get('severity') or
                row_lower.get('level') or 'LOW'
            ).strip().upper()

            message = (
                row_lower.get('message') or
                row_lower.get('description') or
                row_lower.get('issue') or ''
            ).strip()

            if not file_path or not rule_id:
                skipped += 1
                continue

            try:
                line_number = int(line_str)
            except ValueError:
                line_number = 0

            cwe = get_cwe_for_rule(rule_id)

            if not cwe:
                no_cwe += 1
                # Still insert but with NULL cwe so we can audit later
                cwe = None

            program_id = get_program_id_for_file(conn, file_path)

            # Deduplication check
            existing = None
            if cwe:
                existing = c.execute('''
                    SELECT id, tool_count FROM static_results
                    WHERE file_path = ?
                    AND line_number = ?
                    AND cwe = ?
                ''', (file_path, line_number, cwe)).fetchone()

            if existing:
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
                     rule_id, cwe, severity, message,
                     tool_count, static_flagged)
                    VALUES (?, ?, 'devaic', ?, ?, ?, ?, ?, 1, 1)
                ''', (program_id, file_path, line_number,
                      rule_id, cwe, severity, message))
                inserted += 1

    conn.commit()
    print(f"  devaic : {inserted} new findings, "
          f"{updated} duplicates merged, "
          f"{skipped} skipped, "
          f"{no_cwe} findings with unmapped CWE")
    return inserted

def run_ingest(csv_path):
    conn = sqlite3.connect('corpus.db')
    print(f"\nIngesting DeVAIC results from: {csv_path}")
    count = ingest_devaic(csv_path, conn)
    print(f"  Total static_results rows: "
          f"{conn.execute('SELECT COUNT(*) FROM static_results').fetchone()[0]}")
    conn.close()
    return count

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python3 scripts/ingest_devaic.py <devaic_csv_file>")
        print("")
        print("Example:")
        print("  python3 scripts/ingest_devaic.py results/devaic_results.csv")
        sys.exit(1)

    run_ingest(sys.argv[1])
