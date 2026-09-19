import os
import sqlite3
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns

def generate_overlap_plot():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    db_path = os.path.join(base_dir, 'corpus.db')
    conn = sqlite3.connect(db_path)
    
    # Read the exact cell labels generated in the Three-Pillar matrix
    df = pd.read_sql_query("SELECT cell_label, COUNT(*) as count FROM pillar_matrix GROUP BY cell_label", conn)
    conn.close()
    
    if df.empty:
        print("pillar_matrix is empty.")
        return
        
    # Sort for better visual presentation
    df = df.sort_values(by='count', ascending=False)
    
    # Generate a clean, publication-ready bar chart
    plt.figure(figsize=(10, 6), dpi=300)
    colors = sns.color_palette("mako", len(df))
    ax = sns.barplot(data=df, x='cell_label', y='count', palette=colors)
    
    for p in ax.patches:
        height = p.get_height()
        if height > 0:
            ax.annotate(f'{int(height)}',
                        (p.get_x() + p.get_width() / 2., height),
                        ha='center', va='bottom',
                        xytext=(0, 3), textcoords='offset points',
                        fontweight='bold', fontsize=10)
                        
    plt.title("Figure 1: Three-Pillar Agreement (Overlap Distribution)", fontsize=14, fontweight='bold', pad=15)
    plt.xlabel("Agreement Category (Static / Formal / Dynamic)", fontsize=12, fontweight='bold')
    plt.ylabel("Number of Programs", fontsize=12, fontweight='bold')
    plt.xticks(rotation=45, ha='right', fontsize=10)
    plt.tight_layout()
    
    # Save to the exact filename required
    output_path = os.path.join(base_dir, 'results', 'pillar_agreement_upset.png')
    plt.savefig(output_path, dpi=300)
    plt.close()
    print(f"Figure 1 successfully saved to {output_path}")

if __name__ == "__main__":
    generate_overlap_plot()