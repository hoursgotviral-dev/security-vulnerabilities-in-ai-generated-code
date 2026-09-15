"""
overconfidence_summary.py  — Student B (Day 12)
-----------------------------------------------
Aggregates and summarizes overconfidence metrics across models:
1. Calculates overall overconfidence rate.
2. Breaks down overconfidence rate by AI model (Copilot vs ChatGPT).
3. Breaks down overconfidence by language (C, Python, JavaScript).
4. Computes mean confidence scores on vulnerable vs non-vulnerable code.
5. Saves results to results/overconfidence_summary.json.
"""

import os
import sys
import sqlite3
import json

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
DB_PATH  = os.path.join(BASE_DIR, 'corpus.db')
RESULTS_DIR = os.path.join(BASE_DIR, 'results')
os.makedirs(RESULTS_DIR, exist_ok=True)

def generate_overconfidence_summary():
    print("=" * 70)
    print("DAY 12: GENERATING OVERCONFIDENCE PROXY SUMMARY")
    print("=" * 70)
    
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    
    total = cur.execute("SELECT COUNT(*) FROM overconfidence_proxy").fetchone()[0]
    if total == 0:
        print("No records in overconfidence_proxy table.")
        conn.close()
        return
        
    total_overconf = cur.execute("SELECT COUNT(*) FROM overconfidence_proxy WHERE is_overconfident = 1").fetchone()[0]
    total_vulnerable = cur.execute("SELECT COUNT(*) FROM overconfidence_proxy WHERE empirical_vulnerable = 1").fetchone()[0]
    
    # Model breakdown
    cur.execute("""
    SELECT model, 
           COUNT(*),
           SUM(is_overconfident),
           AVG(confidence_score),
           SUM(empirical_vulnerable)
    FROM overconfidence_proxy
    GROUP BY model
    """)
    model_stats = {}
    for model, m_total, m_overconf, m_avg_conf, m_vuln in cur.fetchall():
        model_stats[model] = {
            "total_evals": m_total,
            "vulnerable_count": m_vuln,
            "overconfident_count": m_overconf,
            "overconfidence_rate_pct": round((m_overconf / max(m_vuln, 1)) * 100, 2),
            "mean_confidence": round(m_avg_conf, 3)
        }
        
    # Language breakdown
    cur.execute("""
    SELECT language,
           COUNT(*),
           SUM(is_overconfident),
           AVG(confidence_score)
    FROM overconfidence_proxy
    GROUP BY language
    """)
    lang_stats = {}
    for lang, l_total, l_overconf, l_avg_conf in cur.fetchall():
        lang_stats[lang] = {
            "total_evals": l_total,
            "overconfident_count": l_overconf,
            "overconfidence_rate_pct": round((l_overconf / max(l_total, 1)) * 100, 2),
            "mean_confidence": round(l_avg_conf, 3)
        }

    # Mean confidence comparison
    avg_conf_vuln = cur.execute("SELECT AVG(confidence_score) FROM overconfidence_proxy WHERE empirical_vulnerable = 1").fetchone()[0] or 0.0
    avg_conf_safe = cur.execute("SELECT AVG(confidence_score) FROM overconfidence_proxy WHERE empirical_vulnerable = 0").fetchone()[0] or 0.0
    
    summary = {
        "total_proxy_evaluations": total,
        "total_empirically_vulnerable_evals": total_vulnerable,
        "total_overconfident_errors": total_overconf,
        "overall_overconfidence_rate_pct": round((total_overconf / max(total_vulnerable, 1)) * 100, 2),
        "mean_confidence_on_vulnerable_code": round(avg_conf_vuln, 3),
        "mean_confidence_on_safe_code": round(avg_conf_safe),
        "confidence_calibration_gap": round(avg_conf_vuln - avg_conf_safe, 3),
        "per_model_breakdown": model_stats,
        "per_language_breakdown": lang_stats
    }
    
    out_json = os.path.join(RESULTS_DIR, "overconfidence_summary.json")
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=4)
        
    print(f"\nOverconfidence Summary saved to: {out_json}")
    print(f"  Overall Overconfidence Rate: {summary['overall_overconfidence_rate_pct']}%")
    print("  Per-Model Overconfidence Rates:")
    for m, d in model_stats.items():
        print(f"    - {m:<15}: {d['overconfidence_rate_pct']}% (Mean Conf: {d['mean_confidence']})")
    print("=" * 70)
    conn.close()

if __name__ == "__main__":
    generate_overconfidence_summary()
