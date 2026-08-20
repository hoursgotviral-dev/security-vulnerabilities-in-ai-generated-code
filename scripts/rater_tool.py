"""
rater_tool.py  — Student A/B (fixed)
--------------------------------------
Interactive CLI for rating raw_files as genuinely AI-generated.

Fixes vs original:
  - Absolute DB_PATH derived from __file__ (was hardcoded 'corpus.db')
  - --rater flag lets either student specify their ID without editing code
  - Progress header shows CWE distribution of remaining unrated files
  - 'progress' subcommand shows full cross-rater agreement table
  - 'export' subcommand dumps all rater_decisions to CSV

Usage:
  python scripts/rater_tool.py --rater rater_A           # rate as Student A
  python scripts/rater_tool.py --rater rater_B           # rate as Student B
  python scripts/rater_tool.py --rater rater_A --limit 50
  python scripts/rater_tool.py progress                  # show agreement stats
  python scripts/rater_tool.py export                    # export to CSV
"""

import sqlite3
import sys
import os
import csv
from datetime import datetime

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
DB_PATH  = os.path.join(BASE_DIR, 'corpus.db')

# Default rater ID — override with --rater flag
DEFAULT_RATER = "rater_A"


def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')


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


def run_rater(rater_id: str, limit: int = 100):
    conn = sqlite3.connect(DB_PATH)
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
        ORDER BY r.id
        LIMIT ?
    ''', (rater_id, limit)).fetchall()

    if not rows:
        print("No files left to rate. Either all files have been rated")
        print("or there are no files in the database yet.")
        conn.close()
        return

    print(f"\nFound {len(rows)} files to rate.")
    print(f"Rating as: {rater_id}")
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
            (rater_id,)
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
        ''', (file_id, rater_id, decision, note, datetime.now().isoformat()))
        conn.commit()
        rated += 1

    total = c.execute(
        'SELECT COUNT(*) FROM rater_decisions WHERE rater_id = ?',
        (rater_id,)
    ).fetchone()[0]

    conn.close()
    print(f"\nSession complete.")
    print(f"Rated this session : {rated}")
    print(f"Skipped            : {skipped}")
    print(f"Total rated so far : {total}")


def show_progress(rater_id: str):
    conn = sqlite3.connect(DB_PATH)
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
        (rater_id,)
    ).fetchone()[0]
    print(f"\nTotal files in database : {total}")
    print(f"Rated by {rater_id:<10}    : {rated}")

    # Cross-rater agreement table
    print("\n=== CROSS-RATER AGREEMENT ===")
    pairs = c.execute('''
        SELECT a.decision, b.decision, COUNT(*)
        FROM rater_decisions a
        JOIN rater_decisions b ON a.file_id = b.file_id
        WHERE a.rater_id = 'rater_A' AND b.rater_id = 'rater_B'
        GROUP BY a.decision, b.decision
        ORDER BY a.decision, b.decision
    ''').fetchall()
    if pairs:
        agree = sum(cnt for a, b, cnt in pairs if a == b)
        total_pairs = sum(cnt for _, _, cnt in pairs)
        print(f"  {'A\\B':<6} {'Y':<6} {'N':<6} {'U':<6}")
        from collections import defaultdict
        tbl = defaultdict(lambda: defaultdict(int))
        for a, b, cnt in pairs:
            tbl[a][b] = cnt
        for row_d in ['Y', 'N', 'U']:
            print(f"  {row_d:<6} {tbl[row_d]['Y']:<6} {tbl[row_d]['N']:<6} {tbl[row_d]['U']:<6}")
        if total_pairs:
            print(f"\n  Agreement rate: {agree}/{total_pairs} = {agree/total_pairs*100:.1f}%")
    else:
        print("  No cross-rater pairs yet.")
    conn.close()


def export_decisions(rater_id: str):
    """Export all rater_decisions to CSV."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    rows = c.execute('''
        SELECT file_id, rater_id, decision, note, timestamp
        FROM rater_decisions
        ORDER BY rater_id, file_id
    ''').fetchall()
    conn.close()

    out_path = os.path.join(BASE_DIR, 'results', 'rater_decisions_export.csv')
    with open(out_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['file_id', 'rater_id', 'decision', 'note', 'timestamp'])
        writer.writerows(rows)
    print(f"Exported {len(rows)} decisions to {out_path}")


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description="Interactive rater tool for AI-generated code corpus")
    parser.add_argument('command', nargs='?', default='rate',
                        choices=['rate', 'progress', 'export'],
                        help="Subcommand: rate (default), progress, export")
    parser.add_argument('--rater', type=str, default=DEFAULT_RATER,
                        help=f"Rater ID (default: {DEFAULT_RATER})")
    parser.add_argument('--limit', type=int, default=100,
                        help="Number of files to rate per session (default: 100)")
    args = parser.parse_args()

    if args.command == 'progress':
        show_progress(args.rater)
    elif args.command == 'export':
        export_decisions(args.rater)
    else:
        run_rater(rater_id=args.rater, limit=args.limit)
