import sqlite3
import sys
import os
from datetime import datetime

RATER_ID = "rater_B"  # Change to rater_A when Student A uses this

def clear_screen():
    os.system('clear')

def show_file(file_id, repo_name, file_path, language, ai_tool, keyword, content):
    clear_screen()
    print("=" * 70)
    print(f"FILE ID    : {file_id}")
    print(f"REPO       : {repo_name}")
    print(f"PATH       : {file_path}")
    print(f"LANGUAGE   : {language}")
    print(f"AI TOOL    : {ai_tool}")
    print(f"KEYWORD    : {keyword}")
    print("=" * 70)
    print("CONTENT PREVIEW (first 40 lines):")
    print("-" * 70)

    if content:
        lines = content.splitlines()[:40]
        for i, line in enumerate(lines, 1):
            print(f"  {i:3d} | {line}")
        if len(content.splitlines()) > 40:
            print(f"  ... ({len(content.splitlines()) - 40} more lines not shown)")
    else:
        print("  [No content available]")

    print("-" * 70)

def get_decision():
    while True:
        print("\nIs this file genuinely AI-generated?")
        print("  Y = Yes, clearly AI-generated")
        print("  N = No, not AI-generated or attribution is fake")
        print("  U = Uncertain, cannot tell")
        print("  S = Skip this file for now")
        print("  Q = Quit and save progress")
        print()
        choice = input("Your decision [Y/N/U/S/Q]: ").strip().upper()

        if choice in ('Y', 'N', 'U', 'S', 'Q'):
            if choice == 'Q':
                return 'Q', ''
            if choice == 'S':
                return 'S', ''
            note = input("Add a note (optional, press Enter to skip): ").strip()
            return choice, note
        else:
            print("Invalid input. Please type Y, N, U, S, or Q.")

def run_rater(limit=100):
    conn = sqlite3.connect('corpus.db')
    c = conn.cursor()

    # Get files that this rater hasn't rated yet
    rows = c.execute('''
        SELECT r.id, r.repo_name, r.file_path, r.language,
               r.ai_tool, r.search_keyword, r.file_content
        FROM raw_files r
        WHERE r.id NOT IN (
            SELECT file_id FROM rater_decisions
            WHERE rater_id = ?
        )
        LIMIT ?
    ''', (RATER_ID, limit)).fetchall()

    if not rows:
        print("No files left to rate. Either all files have been rated")
        print("or there are no files in the database yet.")
        conn.close()
        return

    print(f"\nFound {len(rows)} files to rate.")
    print(f"Rating as: {RATER_ID}")
    print("Press Enter to begin...")
    input()

    rated = 0
    skipped = 0

    for row in rows:
        file_id, repo_name, file_path, language, ai_tool, keyword, content = row

        show_file(file_id, repo_name, file_path, language, ai_tool, keyword, content)

        # Show progress
        total_rated = c.execute(
            'SELECT COUNT(*) FROM rater_decisions WHERE rater_id = ?',
            (RATER_ID,)
        ).fetchone()[0]
        print(f"\nProgress: {total_rated} rated so far | {rated} in this session")

        decision, note = get_decision()

        if decision == 'Q':
            print(f"\nQuitting. Rated {rated} files in this session.")
            break

        if decision == 'S':
            skipped += 1
            continue

        # Save decision
        c.execute('''
            INSERT OR REPLACE INTO rater_decisions
            (file_id, rater_id, decision, note, timestamp)
            VALUES (?, ?, ?, ?, ?)
        ''', (file_id, RATER_ID, decision, note, datetime.now().isoformat()))
        conn.commit()
        rated += 1

    total = c.execute(
        'SELECT COUNT(*) FROM rater_decisions WHERE rater_id = ?',
        (RATER_ID,)
    ).fetchone()[0]

    conn.close()
    print(f"\nSession complete.")
    print(f"Rated this session : {rated}")
    print(f"Skipped            : {skipped}")
    print(f"Total rated so far : {total}")

def show_progress():
    conn = sqlite3.connect('corpus.db')
    c = conn.cursor()

    print("\n=== RATING PROGRESS ===")
    for row in c.execute(
        'SELECT rater_id, decision, COUNT(*) FROM rater_decisions '
        'GROUP BY rater_id, decision ORDER BY rater_id, decision'
    ).fetchall():
        print(f"  {row[0]:<12} | {row[1]} | {row[2]}")

    total = c.execute('SELECT COUNT(*) FROM raw_files').fetchone()[0]
    rated = c.execute(
        'SELECT COUNT(DISTINCT file_id) FROM rater_decisions WHERE rater_id = ?',
        (RATER_ID,)
    ).fetchone()[0]
    print(f"\nTotal files in database : {total}")
    print(f"Rated by {RATER_ID:<10}    : {rated}")
    conn.close()

if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'progress':
        show_progress()
    else:
        limit = int(sys.argv[1]) if len(sys.argv) > 1 else 100
        run_rater(limit)
