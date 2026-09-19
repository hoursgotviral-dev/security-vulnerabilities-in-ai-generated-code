"""
static_overlap.py  — Student B (Days 13-14)
-------------------------------------------
Analyzes multi-engine static analysis tool overlap and generates Figure 4:
1. Cross-tabulates findings across CodeQL, Bandit, Flawfinder, Semgrep, and JSSecurityEngine.
2. Identifies unique vs agreed static findings across engines.
3. Renders publication Figure 4:
   - results/static_tool_overlap.png
   - results/static_tool_overlap.pdf
"""

import os
import sys
import sqlite3
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
DB_PATH  = os.path.join(BASE_DIR, 'corpus.db')
RESULTS_DIR = os.path.join(BASE_DIR, 'results')
os.makedirs(RESULTS_DIR, exist_ok=True)

def generate_static_tool_overlap_figure():
    print("=" * 70)
    print("DAYS 13-14: GENERATING FIGURE 4 (STATIC TOOL OVERLAP)")
    print("=" * 70)
    
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    
    # Query tool finding counts
    cur.execute("""
    SELECT tool, COUNT(DISTINCT program_id) as program_count, COUNT(*) as total_findings
    FROM static_results
    GROUP BY tool
    ORDER BY total_findings DESC
    """)
    rows = cur.fetchall()
    
    # Query multi-tool agreement counts
    cur.execute("""
    SELECT program_id, COUNT(DISTINCT tool) as tool_count
    FROM static_results
    GROUP BY program_id
    """)
    prog_tool_counts = cur.fetchall()
    conn.close()
    
    agreement_dist = {}
    for pid, tc in prog_tool_counts:
        agreement_dist[f"{tc} Tool{'s' if tc > 1 else ''}"] = agreement_dist.get(f"{tc} Tool{'s' if tc > 1 else ''}", 0) + 1
        
    tools = [r[0] for r in rows]
    finding_counts = [r[2] for r in rows]
    prog_counts = [r[1] for r in rows]
    
    # Plot dual-panel Figure 4
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5.5), dpi=300)
    plt.style.use('seaborn-v0_8-whitegrid' if 'seaborn-v0_8-whitegrid' in plt.style.available else 'default')
    
    # Panel A: Static Tool Volume
    colors_tools = ['#2b5c8f', '#d95f02', '#7570b3', '#e7298a', '#66a61e']
    bars1 = ax1.bar(tools, prog_counts, color=colors_tools[:len(tools)], edgecolor='black', alpha=0.85)
    ax1.set_title("A: Programs Flagged by Static Engine", fontsize=12, fontweight='bold', pad=12)
    ax1.set_ylabel("Unique Programs Flagged", fontsize=11, fontweight='bold')
    ax1.tick_params(axis='x', rotation=30)
    for b in bars1:
        h = b.get_height()
        ax1.text(b.get_x() + b.get_width()/2., h + 15, f"{int(h):,}", ha='center', va='bottom', fontsize=9, fontweight='bold')

    # Panel B: Inter-Engine Agreement Distribution
    labels = list(agreement_dist.keys())
    counts = list(agreement_dist.values())
    colors_agree = sns.color_palette("mako", len(labels))
    bars2 = ax2.bar(labels, counts, color=colors_agree, edgecolor='black', alpha=0.85)
    ax2.set_title("B: Static Inter-Tool Program Agreement", fontsize=12, fontweight='bold', pad=12)
    ax2.set_ylabel("Number of Programs", fontsize=11, fontweight='bold')
    ax2.set_xlabel("Engine Concurrence", fontsize=11, fontweight='bold')
    for b in bars2:
        h = b.get_height()
        ax2.text(b.get_x() + b.get_width()/2., h + 15, f"{int(h):,}", ha='center', va='bottom', fontsize=9, fontweight='bold')

    plt.suptitle("Figure 4: Multi-Tool Static Analysis Volume & Inter-Tool Overlap", fontsize=14, fontweight='bold', y=1.02)
    plt.tight_layout()
    
    png_path = os.path.join(RESULTS_DIR, "static_tool_overlap.png")
    pdf_path = os.path.join(RESULTS_DIR, "static_tool_overlap.pdf")
    plt.savefig(png_path, dpi=300, bbox_inches='tight')
    plt.savefig(pdf_path, dpi=300, bbox_inches='tight')
    plt.close()
    
    print(f"Figure 4 PNG saved to: {png_path}")
    print(f"Figure 4 PDF saved to: {pdf_path}")
    print("=" * 70)

if __name__ == "__main__":
    generate_static_tool_overlap_figure()
