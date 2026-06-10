import sqlite3
import hashlib
import os

NON_CODE_EXTENSIONS = [
    '.md', '.txt', '.rst', '.json', '.yaml', '.yml',
    '.toml', '.cfg', '.ini', '.csv', '.html', '.xml'
]

MIN_FILE_SIZE_BYTES = 150

def get_file_extension(file_path):
    _, ext = os.path.splitext(file_path.lower())
    return ext

def content_hash(content):
    if content is None:
        return None
    return hashlib.sha256(content.encode('utf-8')).hexdigest()

def run_stage1_filter():
    conn = sqlite3.connect('corpus.db')
    c = conn.cursor()

    rows = c.execute(
        'SELECT r.id, r.file_path, r.language, r.file_content, '
        '       r.keyword_in_comment, r.ai_tool '
        'FROM raw_files r '
        'LEFT JOIN filtered_files f ON r.id = f.raw_file_id '
        'WHERE f.id IS NULL AND r.keyword_in_comment IS NOT NULL'
    ).fetchall()

    print(f'Running Stage 1 filter on {len(rows)} files...')

    seen_hashes = set()
    passed = 0
    rejected = 0

    prog_counter = int(c.execute(
        'SELECT COUNT(*) FROM filtered_files'
    ).fetchone()[0])

    model_map = {
        'copilot': 'copilot', 'chatgpt': 'chatgpt',
        'gpt4': 'gpt4', 'gemini': 'gemini', 'deepseek': 'deepseek'
    }

    for row_id, file_path, language, content, kw_in_comment, ai_tool in rows:
        stage1 = 'PASSED'
        reason = None

        ext = get_file_extension(file_path)
        if ext in NON_CODE_EXTENSIONS:
            stage1 = 'REJECTED'
            reason = 'NON_CODE_EXTENSION'

        elif content is None or len(content.encode('utf-8')) < MIN_FILE_SIZE_BYTES:
            stage1 = 'REJECTED'
            reason = 'TOO_SMALL'

        elif kw_in_comment == 0:
            stage1 = 'REJECTED'
            reason = 'KEYWORD_NOT_IN_COMMENT'

        else:
            h = content_hash(content)
            if h in seen_hashes:
                stage1 = 'REJECTED'
                reason = 'DUPLICATE'
            else:
                seen_hashes.add(h)

        prog_counter += 1
        program_id = f'prog_{prog_counter:06d}'
        model = model_map.get(ai_tool, ai_tool)

        c.execute('''
            INSERT OR IGNORE INTO filtered_files
            (raw_file_id, program_id, file_path, language, model,
             source, stage1, stage1_reason)
            VALUES (?, ?, ?, ?, ?, 'GITHUB', ?, ?)
        ''', (row_id, program_id, file_path, language, model, stage1, reason))

        if stage1 == 'PASSED':
            passed += 1
        else:
            rejected += 1

    conn.commit()

    print(f'Stage 1 complete: {passed} passed, {rejected} rejected')
    print('Breakdown:')
    for row in c.execute(
        'SELECT stage1, stage1_reason, COUNT(*) FROM filtered_files '
        'GROUP BY stage1, stage1_reason ORDER BY COUNT(*) DESC'
    ).fetchall():
        print(f'  {row[0]} | {row[1]} | {row[2]}')

    conn.close()

if __name__ == '__main__':
    run_stage1_filter()
