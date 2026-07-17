import json
import sqlite3
import os

DB_PATH = '../corpus.db'
BANDIT_FILE = '../results/test_bandit.json'
CORRECTIONS_FILE = 'bandit_cwe_corrections.json'

def ingest_bandit():
    if not os.path.exists(BANDIT_FILE):
        print("Bandit test file not found. Skipping.")
        return

    # Load Day 3 manual CWE corrections
    corrections = {}
    if os.path.exists(CORRECTIONS_FILE):
        with open(CORRECTIONS_FILE, 'r') as f:
            corrections = json.load(f)

    with open(BANDIT_FILE, 'r') as f:
        data = json.load(f)

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    count = 0
    corrections_applied = 0

    for result in data.get('results', []):
        rule_id = result.get('test_id')
        file_path = result.get('filename')
        line_num = result.get('line_number')
        severity = result.get('issue_severity')
        
        # Apply the correction map logic
        mapped_cwe = corrections.get(rule_id, "UNCATEGORIZED")
        cwe_corrected = 1 if rule_id in corrections else 0
        if cwe_corrected:
            corrections_applied += 1
        
        cursor.execute('''
            INSERT INTO static_results (program_id, file_path, line_number, rule_id, cwe, severity, tool, cwe_corrected)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (1, file_path, line_num, rule_id, mapped_cwe, severity, 'Bandit', cwe_corrected))
        count += 1

    conn.commit()
    conn.close()
    print(f"Ingested {count} Bandit findings. Applied {corrections_applied} manual CWE overrides.")

if __name__ == "__main__":
    ingest_bandit()
