CREATE TABLE IF NOT EXISTS raw_files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    repo_name TEXT NOT NULL,
    file_path TEXT NOT NULL,
    commit_sha TEXT,
    star_count INTEGER,
    language TEXT,
    raw_url TEXT,
    search_keyword TEXT,
    ai_tool TEXT,
    file_content TEXT,
    keyword_in_comment INTEGER DEFAULT NULL,
    collected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(repo_name, file_path, commit_sha)
);

CREATE TABLE IF NOT EXISTS filtered_files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    raw_file_id INTEGER REFERENCES raw_files(id),
    program_id TEXT UNIQUE NOT NULL,
    file_path TEXT,
    language TEXT,
    model TEXT,
    source TEXT,
    cwe_target TEXT,
    prompt_id TEXT,
    stage1 TEXT,
    stage1_reason TEXT,
    stage2 TEXT,
    compile_status TEXT,
    loc INTEGER,
    content_path TEXT
);

CREATE TABLE IF NOT EXISTS static_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program_id TEXT REFERENCES filtered_files(program_id),
    file_path TEXT,
    tool TEXT,
    line_number INTEGER,
    rule_id TEXT,
    cwe TEXT,
    cwe_corrected INTEGER DEFAULT 0,
    severity TEXT,
    message TEXT,
    tool_count INTEGER DEFAULT 1,
    fp_risk_level TEXT,
    flawfinder_flagged INTEGER DEFAULT 0,
    static_flagged INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS formal_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program_id TEXT REFERENCES filtered_files(program_id),
    cbmc_result TEXT,
    property_type TEXT,
    cwe TEXT,
    counterexample_json TEXT,
    asan_harness_result TEXT,
    not_confirmed_reason TEXT,
    klee_seeding TEXT,
    klee_paths_explored INTEGER,
    klee_test_cases INTEGER,
    klee_direct_crash INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS dynamic_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program_id TEXT REFERENCES filtered_files(program_id),
    afl_crashed INTEGER DEFAULT 0,
    afl_hang INTEGER DEFAULT 0,
    confirmed_crash_count INTEGER DEFAULT 0,
    unique_crash_hashes TEXT,
    dynamic_cwe TEXT,
    hang_cwe TEXT,
    hang_confirmed INTEGER DEFAULT 0,
    edge_coverage_pct REAL,
    time_to_first_crash_seconds REAL,
    seed_type TEXT,
    msan_result TEXT,
    atheris_crashed INTEGER DEFAULT 0,
    atheris_exception_type TEXT,
    taint_flows TEXT,
    final_injection_confirmed INTEGER DEFAULT 0,
    libfuzzer_differential INTEGER DEFAULT 0,
    classification TEXT,
    compile_status TEXT
);

CREATE TABLE IF NOT EXISTS pillar_matrix (
    program_id TEXT PRIMARY KEY REFERENCES filtered_files(program_id),
    model TEXT,
    language TEXT,
    static_flagged INTEGER DEFAULT 0,
    cbmc_sat INTEGER DEFAULT 0,
    asan_confirmed INTEGER DEFAULT 0,
    afl_crashed INTEGER DEFAULT 0,
    dynamic_cwe TEXT,
    edge_coverage_pct REAL,
    classification TEXT,
    cell_label TEXT
);

CREATE TABLE IF NOT EXISTS rater_decisions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id INTEGER REFERENCES raw_files(id),
    rater_id TEXT,
    decision TEXT,
    note TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS overconfidence_proxy (
    program_id TEXT REFERENCES filtered_files(program_id),
    model TEXT,
    response TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
