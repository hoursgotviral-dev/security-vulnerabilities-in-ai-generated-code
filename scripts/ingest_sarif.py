import sqlite3
import json
import sys
import os

def extract_cwe_from_tags(tags):
    """
    SARIF rules store CWE as tags like 'CWE-89' or 'external/cwe/cwe-89'.
    This function finds and returns the first CWE tag it finds.
    """
    for tag in tags:
        tag_upper = tag.upper()
        if 'CWE' in tag_upper:
            # Handle formats: 'CWE-89', 'cwe-89', 'external/cwe/cwe-89'
            parts = tag_upper.replace('/', ' ').split()
            for part in parts:
                if part.startswith('CWE-'):
                    return part  # e.g. 'CWE-89'
    return None

def extract_cwe_from_rule(rule):
    """
    Try to get a CWE from a SARIF rule object.
    Checks properties.tags, properties.cwe, and help text.
    """
    properties = rule.get('properties', {})

    # Check tags array
    tags = properties.get('tags', [])
    cwe = extract_cwe_from_tags(tags)
    if cwe:
        return cwe

    # Check direct cwe property (some tools use this)
    direct_cwe = properties.get('cwe', '')
    if direct_cwe:
        if not direct_cwe.upper().startswith('CWE-'):
            direct_cwe = f'CWE-{direct_cwe}'
        return direct_cwe.upper()

    # Check precision and security-severity (CodeQL specific)
    problem_severity = properties.get('problem.severity', '')
    if problem_severity:
        # Try to get from rule ID if it looks like a CWE
        rule_id = rule.get('id', '')
        if 'cwe' in rule_id.lower():
            return rule_id.upper()

    return None

def get_program_id_for_file(conn, file_path):
    """
    Given a file path from a SARIF result, find the matching program_id
    in filtered_files. Tries exact match first, then basename match.
    """
    c = conn.cursor()

    # Try exact path match
    row = c.execute(
        'SELECT program_id FROM filtered_files WHERE file_path = ?',
        (file_path,)
    ).fetchone()
    if row:
        return row[0]

    # Try basename match (SARIF paths may differ from stored paths)
    basename = os.path.basename(file_path)
    row = c.execute(
        'SELECT program_id FROM filtered_files WHERE file_path LIKE ?',
        (f'%{basename}%',)
    ).fetchone()
    if row:
        return row[0]

    return None

def ingest_sarif(sarif_path, tool_name, conn):
    """
    Parse a SARIF file and insert findings into static_results.
    tool_name should be 'codeql' or 'semgrep'.
    """
    if not os.path.exists(sarif_path):
        print(f"Error: File not found: {sarif_path}")
        return 0

    with open(sarif_path) as f:
        sarif = json.load(f)

    c = conn.cursor()
    inserted = 0
    updated = 0
    skipped = 0

    for run in sarif.get('runs', []):
        # Build a lookup of rule_id -> CWE from the rules section
        rules_by_id = {}
        rules = run.get('tool', {}).get('driver', {}).get('rules', [])
        for rule in rules:
            rule_id = rule.get('id', '')
            cwe = extract_cwe_from_rule(rule)
            rules_by_id[rule_id] = cwe

        # Process each result
        results = run.get('results', [])
        for result in results:
            rule_id  = result.get('ruleId', '')
            message  = result.get('message', {}).get('text', '')
            severity = result.get('level', 'warning')
            cwe      = rules_by_id.get(rule_id)

            # Get file path and line number from locations
            locations = result.get('locations', [])
            if not locations:
                skipped += 1
                continue

            loc = locations[0]
            phys = loc.get('physicalLocation', {})
            artifact = phys.get('artifactLocation', {})
            file_path = artifact.get('uri', '')
            region = phys.get('region', {})
            line_number = region.get('startLine', 0)

            if not file_path:
                skipped += 1
                continue

            # Find matching program_id
            program_id = get_program_id_for_file(conn, file_path)

            # Check if this finding already exists from another tool
            # Deduplication key: (file_path, line_number, cwe)
            existing = c.execute('''
                SELECT id, tool_count FROM static_results
                WHERE file_path = ?
                AND line_number = ?
                AND cwe = ?
            ''', (file_path, line_number, cwe)).fetchone()

            if existing and cwe:
                # Another tool already found this — increment tool_count
                c.execute('''
                    UPDATE static_results
                    SET tool_count = tool_count + 1
                    WHERE id = ?
                ''', (existing[0],))
                updated += 1
            else:
                # New finding — insert it
                c.execute('''
                    INSERT INTO static_results
                    (program_id, file_path, tool, line_number,
                     rule_id, cwe, severity, message,
                     tool_count, static_flagged)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, 1)
                ''', (program_id, file_path, tool_name,
                      line_number, rule_id, cwe,
                      severity, message))
                inserted += 1

    conn.commit()
    print(f"  {tool_name}: {inserted} new findings, {updated} duplicates merged, {skipped} skipped")
    return inserted

def run_ingest(sarif_path, tool_name):
    conn = sqlite3.connect('corpus.db')
    print(f"\nIngesting {tool_name} results from: {sarif_path}")
    count = ingest_sarif(sarif_path, tool_name, conn)
    print(f"  Total static_results rows: "
          f"{conn.execute('SELECT COUNT(*) FROM static_results').fetchone()[0]}")
    conn.close()
    return count

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: python3 scripts/ingest_sarif.py <sarif_file> <tool_name>")
        print("  tool_name: codeql or semgrep")
        print("")
        print("Examples:")
        print("  python3 scripts/ingest_sarif.py results/codeql_c.sarif codeql")
        print("  python3 scripts/ingest_sarif.py results/semgrep_py.sarif semgrep")
        sys.exit(1)

    sarif_file = sys.argv[1]
    tool       = sys.argv[2].lower()

    if tool not in ('codeql', 'semgrep'):
        print(f"Error: tool_name must be 'codeql' or 'semgrep', got '{tool}'")
        sys.exit(1)

    run_ingest(sarif_file, tool)
