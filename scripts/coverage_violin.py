"""
coverage_violin.py  — Student A & B (Days 13-14)
------------------------------------------------
Generates edge coverage violin plot / distribution figure:
1. Extracts edge coverage percentages grouped by language (C, Python, JavaScript).
2. Uses matplotlib to render violin / boxplot distributions.
3. Saves high-resolution publication figure to results/coverage_violin.png.
"""

import os
import sys
import sqlite3
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
DB_PATH  = os.path.join(BASE_DIR, 'corpus.db')
RESULTS_DIR = os.path.join(BASE_DIR, 'results')
os.makedirs(RESULTS_DIR, exist_ok=True)

def generate_coverage_violin():
    print("=" * 70)
    print("DAYS 13-14: GENERATING EDGE COVERAGE VIOLIN PLOT")
    print("=" * 70)
    
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    
    cur.execute("""
    SELECT language, edge_coverage_pct 
    FROM pillar_matrix
    WHERE edge_coverage_pct IS NOT NULL
    """)
    rows = cur.fetchall()
    conn.close()
    
    if not rows:
        print("No edge coverage data found in pillar_matrix.")
        return
        
    data_by_lang = {}
    for lang, cov in rows:
        data_by_lang.setdefault(lang, []).append(cov)
        
    langs = list(data_by_lang.keys())
    data = [data_by_lang[l] for l in langs]
    
    plt.figure(figsize=(9, 6), dpi=300)
    plt.style.use('seaborn-v0_8-whitegrid' if 'seaborn-v0_8-whitegrid' in plt.style.available else 'default')
    
    parts = plt.violinplot(data, showmeans=True, showmedians=True, showextrema=True)
    
    # Custom styling
    colors = ['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728']
    for i, pc in enumerate(parts['bodies']):
        pc.set_facecolor(colors[i % len(colors)])
        pc.set_edgecolor('black')
        pc.set_alpha(0.7)
        
    parts['cmeans'].set_color('red')
    parts['cmedians'].set_color('black')
    
    plt.xticks(range(1, len(langs) + 1), langs, fontsize=12, fontweight='bold')
    plt.ylabel('Edge Coverage (%)', fontsize=12, fontweight='bold')
    plt.title('Dynamic Execution Edge Coverage Distribution by Language', fontsize=14, fontweight='bold', pad=15)
    plt.ylim(0, 105)
    
    # Annotate means
    for i, l in enumerate(langs):
        mean_val = np.mean(data_by_lang[l])
        plt.text(i + 1, min(mean_val + 4, 102), f'Mean: {mean_val:.1f}%', 
                 ha='center', fontsize=10, fontweight='semibold', color='darkred')
                 
    plt.tight_layout()
    out_path = os.path.join(RESULTS_DIR, "coverage_violin.png")
    plt.savefig(out_path, dpi=300)
    plt.close()
    print(f"Coverage Violin Plot saved to: {out_path}")

if __name__ == "__main__":
    generate_coverage_violin()
