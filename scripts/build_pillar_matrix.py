import sqlite3

DB_PATH = '../corpus.db'

def build_matrix():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Day 16: Three-way LEFT JOIN
    query = """
    SELECT 
        r.program_id, r.model, r.language,
        CASE WHEN s.static_flagged IS NOT NULL THEN 1 ELSE 0 END as static_flagged,
        CASE WHEN f.cbmc_result = 'SAT' THEN 1 ELSE 0 END as cbmc_sat,
        COALESCE(d.afl_crashed, 0) as afl_crashed,
        COALESCE(d.edge_coverage_pct, 0) as edge_coverage_pct
    FROM raw_files r
    LEFT JOIN (SELECT program_id, 1 as static_flagged FROM static_results GROUP BY program_id) s 
        ON r.program_id = s.program_id
    LEFT JOIN formal_results f ON r.program_id = f.program_id
    LEFT JOIN dynamic_results d ON r.program_id = d.program_id
    WHERE r.language = 'C'
    """
    
    cursor.execute(query)
    rows = cursor.fetchall()
    
    count = 0
    for row in rows:
        prog_id, model, lang, s, f_sat, d, edge = row
        
        # Determine the 8 matrix cells
        if s and f_sat and d: label = 'ALL_THREE'
        elif s and f_sat and not d: label = 'STATIC_FORMAL'
        elif s and not f_sat and d: label = 'STATIC_DYNAMIC'
        elif not s and f_sat and d: label = 'FORMAL_DYNAMIC'
        elif s and not f_sat and not d: label = 'STATIC_ONLY'
        elif not s and f_sat and not d: label = 'FORMAL_ONLY'
        elif not s and not f_sat and d: label = 'DYNAMIC_ONLY'
        else: label = 'NONE'
        
        cursor.execute('''
            INSERT OR REPLACE INTO pillar_matrix 
            (program_id, model, language, static_flagged, cbmc_sat, afl_crashed, edge_coverage_pct, cell_label)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (prog_id, model, lang, s, f_sat, d, edge, label))
        count += 1
        
    conn.commit()
    conn.close()
    print(f"Pillar Matrix built successfully! Classified {count} C programs.")

if __name__ == "__main__":
    build_matrix()