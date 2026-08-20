import sqlite3

conn = sqlite3.connect('corpus.db')

total = conn.execute("SELECT COUNT(*) FROM raw_files WHERE language='C'").fetchone()[0]
null_content = conn.execute("SELECT COUNT(*) FROM raw_files WHERE language='C' AND file_content IS NULL").fetchone()[0]
empty_content = conn.execute("SELECT COUNT(*) FROM raw_files WHERE language='C' AND TRIM(file_content) = ''").fetchone()[0]
tiny = conn.execute("SELECT COUNT(*) FROM raw_files WHERE language='C' AND LENGTH(file_content) < 50").fetchone()[0]
avg_len = conn.execute("SELECT AVG(LENGTH(file_content)) FROM raw_files WHERE language='C'").fetchone()[0]

print(f"Total C rows: {total}")
print(f"NULL content: {null_content}")
print(f"Empty/whitespace-only content: {empty_content}")
print(f"Suspiciously tiny (<50 chars): {tiny}")
print(f"Average content length: {avg_len:.0f} chars")

print()
print("--- Sample of 5 files (repo, path, length) ---")
for row in conn.execute("SELECT repo_name, file_path, LENGTH(file_content) FROM raw_files WHERE language='C' ORDER BY RANDOM() LIMIT 5"):
    print(row)

print()
print("--- First 500 chars of one random file ---")
sample = conn.execute("SELECT file_content FROM raw_files WHERE language='C' ORDER BY RANDOM() LIMIT 1").fetchone()[0]
print(sample[:500] if sample else "(NULL content)")

print()
print("--- Checking for HTML/JSON error pages stored as content ---")
looks_like_html = conn.execute("SELECT COUNT(*) FROM raw_files WHERE language='C' AND file_content LIKE '<!DOCTYPE%'").fetchone()[0]
looks_like_json_error = conn.execute("SELECT COUNT(*) FROM raw_files WHERE language='C' AND file_content LIKE '{\"message\"%'").fetchone()[0]
print(f"Rows starting with <!DOCTYPE (HTML error page): {looks_like_html}")
print(f"Rows starting with JSON error message: {looks_like_json_error}")

conn.close()
