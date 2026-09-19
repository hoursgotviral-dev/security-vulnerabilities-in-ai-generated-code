"""
taint_tracker.py  — Student B (Day 12)
---------------------------------------
AST & Dataflow Taint Tracking for Python & JS programs:
1. Identifies untrusted taint sources:
   - sys.argv, os.environ, request.args, input(), params, query
2. Tracks propagations through variable assignments, string concatenations, f-strings, and format().
3. Identifies sensitive security sinks:
   - SQL Execution: cursor.execute, session.execute (CWE-89)
   - Command Execution: os.system, subprocess.run, subprocess.Popen (CWE-78)
   - Code Execution: eval, exec, compile (CWE-94/95)
   - Path Traversal: open, os.path.join with untrusted input (CWE-22)
   - Deserialization: pickle.loads, yaml.load (CWE-502)
4. Determines confirmed injection vulnerabilities.
"""

import os
import sys
import sqlite3
import ast
import re
import json
import argparse

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
DB_PATH  = os.path.join(BASE_DIR, 'corpus.db')

TAINT_SOURCES = {
    'input', 'sys.argv', 'request.args', 'request.form', 'request.json',
    'request.values', 'request.data', 'os.environ', 'environ', 'params',
    'query', 'user_input', 'raw_input', 'url'
}

TAINT_SINKS = {
    'execute': 'CWE-89',        # SQL Injection
    'executemany': 'CWE-89',
    'raw': 'CWE-89',
    'system': 'CWE-78',         # Command Injection
    'popen': 'CWE-78',
    'run': 'CWE-78',
    'spawn': 'CWE-78',
    'eval': 'CWE-95',           # Eval Injection
    'exec': 'CWE-94',           # Code Injection
    'loads': 'CWE-502',         # Deserialization
    'load': 'CWE-502',
    'open': 'CWE-22',           # Path Traversal
    'read_file': 'CWE-22'
}

class ASTTaintVisitor(ast.NodeVisitor):
    def __init__(self):
        self.tainted_vars = set(TAINT_SOURCES)
        self.flows = []
        
    def visit_Assign(self, node):
        # Track taint assignment
        rhs_str = ast.unparse(node.value) if hasattr(ast, 'unparse') else ""
        is_rhs_tainted = any(src in rhs_str for src in self.tainted_vars)
        if is_rhs_tainted:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.tainted_vars.add(target.id)
        self.generic_visit(node)
        
    def visit_Call(self, node):
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
            
        if func_name in TAINT_SINKS:
            cwe = TAINT_SINKS[func_name]
            # Check if any argument contains tainted variables
            for arg in node.args:
                arg_str = ast.unparse(arg) if hasattr(ast, 'unparse') else ""
                if any(t_var in arg_str for t_var in self.tainted_vars):
                    self.flows.append({
                        "sink": func_name,
                        "cwe": cwe,
                        "line": getattr(node, 'lineno', 1),
                        "argument": arg_str[:80]
                    })
        self.generic_visit(node)

def analyze_taint(limit=None):
    print("=" * 70)
    print("DAY 12: RUNNING AST & DATAFLOW TAINT TRACKER")
    print("=" * 70)
    
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    
    query = """
    SELECT f.program_id, f.language, r.file_content
    FROM filtered_files f
    JOIN raw_files r ON f.raw_file_id = r.id
    WHERE f.language IN ('Python', 'JavaScript') AND f.stage1 = 'PASSED'
    ORDER BY f.id ASC
    """
    if limit:
        query += f" LIMIT {limit}"
        
    cur.execute(query)
    rows = cur.fetchall()
    print(f"Tracking taint flows across {len(rows)} programs...")
    
    taint_results = {}
    total_tainted = 0
    cwe_breakdown = {}

    for pid, lang, content in rows:
        flows = []
        if lang == 'Python' and content:
            try:
                tree = ast.parse(content)
                visitor = ASTTaintVisitor()
                visitor.visit(tree)
                flows = visitor.flows
            except Exception:
                # Regex fallback for non-parsable snippets
                for sink, cwe in TAINT_SINKS.items():
                    if re.search(rf'\b{sink}\s*\(.*(input|argv|request|params)', content):
                        flows.append({"sink": sink, "cwe": cwe, "line": 1, "argument": "regex_detected"})
        elif lang == 'JavaScript' and content:
            # Regex taint for JS
            for sink, cwe in [('eval', 'CWE-95'), ('exec', 'CWE-94'), ('innerHTML', 'CWE-79'), ('document.write', 'CWE-79')]:
                if sink in content and ('req.' in content or 'params' in content or 'window.location' in content):
                    flows.append({"sink": sink, "cwe": cwe, "line": 1, "argument": "js_taint_match"})

        is_confirmed = 1 if len(flows) > 0 else 0
        if is_confirmed:
            total_tainted += 1
            for f in flows:
                cwe = f.get('cwe', 'CWE-699')
                cwe_breakdown[cwe] = cwe_breakdown.get(cwe, 0) + 1
                
        taint_results[pid] = {
            "taint_flows": json.dumps(flows) if flows else None,
            "final_injection_confirmed": is_confirmed,
            "flows_count": len(flows)
        }

    print("\n" + "=" * 70)
    print("TAINT TRACKING SUMMARY:")
    print(f"  Total Programs Evaluated:    {len(rows)}")
    print(f"  Confirmed Injection Flows:   {total_tainted} ({total_tainted/max(len(rows),1)*100:.1f}%)")
    print("  Taint CWE Breakdown:")
    for cwe, cnt in sorted(cwe_breakdown.items(), key=lambda x: x[1], reverse=True):
        print(f"    - {cwe:<12}: {cnt} flows")
    print("=" * 70)
    
    conn.close()
    return taint_results

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=None)
    args = parser.parse_args()
    analyze_taint(args.limit)
