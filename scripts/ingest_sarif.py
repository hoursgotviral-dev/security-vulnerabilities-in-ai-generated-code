import json
import sqlite3
import os

DB_PATH = '../corpus.db'

def ingest_sarif(file_path, tool_name):
    if not os.path.exists(file_path):
        print(f"File {file_path} not found.")
        return

    with open(file_path, 'r') as f:
        data = json.load(f)

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    count = 0

    for run in data.get('runs', []):
        for result in run.get('results', []):
            rule_id = result.get('ruleId', 'UNKNOWN')
            
            # Navigate SARIF structure to find location
            locations = result.get('locations', [])
            if locations:
                phys_loc = locations[0].get('physicalLocation', {})
                file_loc = phys_loc.get('artifactLocation', {}).get('uri', 'unknown')
                line_num = phys_loc.get('region', {}).get('startLine', 0)
                
                # We assign this to program_id 1 for local testing purposes
                cursor.execute('''
                    INSERT INTO static_results (program_id, file_path, line_number, rule_id, cwe, severity, tool)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (1, file_loc, line_num, rule_id, "UNCATEGORIZED", "HIGH", tool_name))
                count += 1
                
    conn.commit()
    conn.close()
    print(f"Ingested {count} SARIF findings from {tool_name}.")

if __name__ == "__main__":
    ingest_sarif('../results/test_sample.sarif', 'CodeQL')