import os
import sqlite3
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns

def generate_heatmap():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    db_path = os.path.join(base_dir, 'corpus.db')
    conn = sqlite3.connect(db_path)
    
    # Join filtered_files and static_results to get Model vs CWE (Top CWEs)
    query = """
    SELECT f.model, s.cwe
    FROM static_results s
    JOIN filtered_files f ON s.program_id = f.program_id
    WHERE s.cwe NOT IN ('UNCATEGORIZED', 'CWE-699')
    """
    df = pd.read_sql_query(query, conn)
    
    if df.empty:
        print("No categorized CWE data found.")
        conn.close()
        return
        
    # Filter to top 10 most frequent CWEs for publication-quality readability
    top_cwes = df['cwe'].value_counts().head(10).index
    df_filtered = df[df['cwe'].isin(top_cwes)]
    
    # Create cross-tabulation matrix
    heatmap_data = pd.crosstab(df_filtered['model'], df_filtered['cwe'])
    
    # Plot using Seaborn
    plt.figure(figsize=(11, 6), dpi=300)
    sns.heatmap(heatmap_data, annot=True, cmap="YlOrRd", cbar_kws={'label': 'Finding Count'}, fmt='d', linewidths=0.5)
    plt.title("Figure 2: Top Vulnerability CWE Frequency by Model", fontsize=14, fontweight='bold', pad=15)
    plt.xlabel("CWE Identifier", fontsize=12, fontweight='bold')
    plt.ylabel("AI Code Generation Model", fontsize=12, fontweight='bold')
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    
    # Save as 300dpi PNG
    output_path = os.path.join(base_dir, 'results', 'cwe_heatmap.png')
    plt.savefig(output_path, dpi=300)
    plt.close()
    print(f"Heatmap saved to {output_path}")
    
    conn.close()

if __name__ == "__main__":
    generate_heatmap()