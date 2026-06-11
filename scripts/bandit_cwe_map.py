import json
import sqlite3

def run_bandit_audit():
    # Load the corrections file
    with open('scripts/bandit_cwe_corrections.json') as f:
        corrections = json.load(f)

    print("=" * 70)
    print("BANDIT CWE AUDIT REPORT")
    print("=" * 70)

    total = 0
    corrected = 0
    verified = 0

    print(f"\n{'Rule':<8} {'Bandit CWE':<12} {'Correct CWE':<13} {'Status':<12} Name")
    print("-" * 70)

    for rule_id, data in corrections.items():
        if rule_id == '_note':
            continue

        total += 1
        bandit_cwe  = data.get('bandit_cwe', 'UNKNOWN')
        correct_cwe = data.get('correct_cwe', 'UNKNOWN')
        name        = data.get('name', '')
        was_corrected = data.get('corrected', False)

        if was_corrected:
            status = 'CORRECTED'
            corrected += 1
        else:
            status = 'VERIFIED'
            verified += 1

        marker = '**' if was_corrected else '  '
        print(f"{marker}{rule_id:<6} {bandit_cwe:<12} {correct_cwe:<13} {status:<12} {name}")

    print("-" * 70)
    print(f"\nTotal rules documented : {total}")
    print(f"Verified correct       : {verified}")
    print(f"Corrected              : {corrected}  (** marked above)")
    print(f"Correction rate        : {corrected/total*100:.1f}%")

    print("\n--- RULES NEEDING MANUAL VERIFICATION ---")
    print("These rules are in the JSON but should be double-checked against NVD:")
    needs_check = [
        rule_id for rule_id, data in corrections.items()
        if rule_id != '_note' and data.get('correct_cwe') == 'UNKNOWN'
    ]
    if needs_check:
        for r in needs_check:
            print(f"  {r}")
    else:
        print("  None — all rules have CWE assignments")

    print("\n--- APPLYING TO DATABASE ---")
    conn = sqlite3.connect('corpus.db')
    c = conn.cursor()

    existing = c.execute(
        'SELECT COUNT(*) FROM static_results WHERE tool = "bandit"'
    ).fetchone()[0]

    if existing == 0:
        print("  No Bandit results in database yet (Day 6+ task)")
        print("  This script will re-apply corrections when Bandit runs")
    else:
        updated = 0
        for rule_id, data in corrections.items():
            if rule_id == '_note':
                continue
            if data.get('corrected'):
                result = c.execute('''
                    UPDATE static_results
                    SET cwe = ?, cwe_corrected = 1
                    WHERE tool = 'bandit' AND rule_id = ?
                ''', (data['correct_cwe'], rule_id))
                updated += result.rowcount
        conn.commit()
        print(f"  Updated {updated} Bandit findings with corrected CWEs")

    conn.close()
    print("\nAudit complete.")

if __name__ == '__main__':
    run_bandit_audit()
