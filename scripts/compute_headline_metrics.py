"""
compute_headline_metrics.py  — Student A & B (Days 13-14)
---------------------------------------------------------
Computes empirical publication headline metrics from corpus.db:
1. Total programs analyzed.
2. Pillar agreement counts and overlap percentages.
3. Novel Static False Positive Rate.
4. Dynamic-only bug discovery count.
5. Per-model vulnerability rates and rankings (Copilot vs ChatGPT).
6. Per-language vulnerability rates.
7. Saves outputs to results/headline_metrics.json and results/per_model_table.csv.
"""

import os
import sys
import sqlite3
import json
import csv

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
DB_PATH  = os.path.join(BASE_DIR, 'corpus.db')
RESULTS_DIR = os.path.join(BASE_DIR, 'results')
os.makedirs(RESULTS_DIR, exist_ok=True)

def compute_headline_metrics():
    print("=" * 70)
    print("DAYS 13-14: COMPUTING FINAL EMPIRICAL HEADLINE METRICS")
    print("=" * 70)
    
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    
    # 1. Total counts from pillar_matrix
    total_analyzed = cur.execute("SELECT COUNT(*) FROM pillar_matrix").fetchone()[0]
    if total_analyzed == 0:
        print("pillar_matrix is empty. Run build_pillar_matrix.py first.")
        conn.close()
        return
        
    # Cell breakdown
    cur.execute("SELECT cell_label, COUNT(*) FROM pillar_matrix GROUP BY cell_label")
    cell_counts = {r[0]: r[1] for r in cur.fetchall()}
    
    # Static FP (Flagged by static tools, but not confirmed by formal or dynamic)
    static_fp_count = cell_counts.get("STATIC_ONLY", 0)
    static_total_flagged = cur.execute("SELECT COUNT(*) FROM pillar_matrix WHERE static_flagged = 1").fetchone()[0]
    static_fp_rate = round((static_fp_count / max(static_total_flagged, 1)) * 100, 2)
    
    # Confirmed Vulnerable (>=2 pillars or dynamic crash)
    cur.execute("SELECT COUNT(*) FROM pillar_matrix WHERE classification = 'CONFIRMED_VULNERABLE'")
    confirmed_vuln = cur.execute("SELECT COUNT(*) FROM pillar_matrix WHERE classification = 'CONFIRMED_VULNERABLE'").fetchone()[0]
    
    # Dynamic Only Discoveries
    dynamic_only_count = cell_counts.get("DYNAMIC_ONLY", 0)
    
    # All Three Agreement
    all_three_count = cell_counts.get("ALL_THREE", 0)
    
    # 2. Per-Model Breakdown
    cur.execute("""
    SELECT model, 
           COUNT(*) as total,
           SUM(static_flagged) as static_cnt,
           SUM(cbmc_sat) as formal_cnt,
           SUM(afl_crashed) as dynamic_cnt,
           SUM(CASE WHEN classification = 'CONFIRMED_VULNERABLE' THEN 1 ELSE 0 END) as conf_cnt,
           SUM(CASE WHEN cell_label = 'STATIC_ONLY' THEN 1 ELSE 0 END) as static_fp_cnt
    FROM pillar_matrix
    GROUP BY model
    ORDER BY total DESC
    """)
    model_stats = {}
    csv_rows = []
    
    for m, m_tot, m_stat, m_form, m_dyn, m_conf, m_fp in cur.fetchall():
        m_vuln_rate = round((m_conf / max(m_tot, 1)) * 100, 2)
        m_fp_rate = round((m_fp / max(m_stat, 1)) * 100, 2)
        model_stats[m] = {
            "total_programs": m_tot,
            "static_flagged": m_stat,
            "formal_sat": m_form,
            "dynamic_confirmed": m_dyn,
            "multi_pillar_confirmed_vulnerable": m_conf,
            "confirmed_vulnerability_rate_pct": m_vuln_rate,
            "static_fp_count": m_fp,
            "static_fp_rate_pct": m_fp_rate
        }
        csv_rows.append([m, m_tot, m_stat, m_form, m_dyn, m_conf, f"{m_vuln_rate}%", m_fp, f"{m_fp_rate}%"])
        
    # 3. Per-Language Breakdown
    cur.execute("""
    SELECT language, 
           COUNT(*) as total,
           SUM(CASE WHEN classification = 'CONFIRMED_VULNERABLE' THEN 1 ELSE 0 END) as conf_cnt
    FROM pillar_matrix
    GROUP BY language
    ORDER BY total DESC
    """)
    lang_stats = {}
    for l, l_tot, l_conf in cur.fetchall():
        lang_stats[l] = {
            "total_programs": l_tot,
            "confirmed_vulnerable": l_conf,
            "vulnerability_rate_pct": round((l_conf / max(l_tot, 1)) * 100, 2)
        }
        
    headline_metrics = {
        "1_total_programs_analyzed": total_analyzed,
        "2_total_static_flagged": static_total_flagged,
        "3_confirmed_vulnerable_count": confirmed_vuln,
        "4_overall_vulnerability_rate_pct": round((confirmed_vuln / max(total_analyzed, 1)) * 100, 2),
        "5_all_three_pillars_agreement_count": all_three_count,
        "6_novel_static_false_positive_count": static_fp_count,
        "7_novel_static_false_positive_rate_pct": static_fp_rate,
        "8_dynamic_only_discoveries_count": dynamic_only_count,
        "9_three_pillar_cells": cell_counts,
        "10_per_model_summary": model_stats,
        "11_per_language_summary": lang_stats,
        "note": "100% empirical, zero-calibration headline metrics."
    }
    
    json_path = os.path.join(RESULTS_DIR, "headline_metrics.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(headline_metrics, f, indent=4)
        
    model_json_path = os.path.join(RESULTS_DIR, "per_model_summary.json")
    with open(model_json_path, "w", encoding="utf-8") as f:
        json.dump(model_stats, f, indent=4)
        
    csv_path = os.path.join(RESULTS_DIR, "per_model_table.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Model", "Total Programs", "Static Flagged", "Formal SAT", "Dynamic Confirmed", "Confirmed Vuln", "Vuln Rate", "Static FP", "Static FP Rate"])
        writer.writerows(csv_rows)
        
    print(f"\nHeadline metrics saved to:  {json_path}")
    print(f"Per-model summary saved to: {model_json_path}")
    print(f"Per-model table saved to:   {csv_path}")
    print("\n" + "=" * 70)
    print("KEY HEADLINE FINDINGS:")
    print(f"  Total Programs Evaluated:          {total_analyzed}")
    print(f"  Confirmed Vulnerabilities:         {confirmed_vuln} ({headline_metrics['4_overall_vulnerability_rate_pct']}%)")
    print(f"  All-Three Pillars Agreement:       {all_three_count}")
    print(f"  Novel Static False Positive Rate:  {static_fp_rate}% ({static_fp_count}/{static_total_flagged})")
    print(f"  Dynamic-Only Vulnerabilities:      {dynamic_only_count}")
    print("=" * 70)
    
    conn.close()

if __name__ == "__main__":
    compute_headline_metrics()