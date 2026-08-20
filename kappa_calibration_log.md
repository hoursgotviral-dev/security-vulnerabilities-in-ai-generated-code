# Kappa Calibration Log

Inter-rater reliability calibration between rater_A (Student A) and rater_B (Student B).

The rating task: given a source file and its `ai_tool` attribution keyword,  
decide whether the file is **genuinely AI-generated** (Y), **not AI-generated** (N),  
or **uncertain** (U).

---

## Round 1 — Calibration Batch (Day 2)

**Date:** 2026-08-20  
**Files rated:** 50 (calibration batch, sampled across all models and languages)  
**Raters:** rater_A, rater_B

### Results

| Metric | Value |
|--------|-------|
| rater_A: Y | — |
| rater_A: N | — |
| rater_A: U | — |
| rater_B: Y | — |
| rater_B: N | — |
| rater_B: U | — |
| **Agreement rate** | — |
| **Cohen's κ** | — |

> Fill in after running `python scripts/kappa.py` post-calibration session.

### Disagreements (Round 1)

Document files where rater_A ≠ rater_B and the resolution:

| file_id | rater_A | rater_B | Resolution | Notes |
|---------|---------|---------|------------|-------|
| — | — | — | — | — |

### Decision Rules Established

After discussion of Round 1 disagreements, the following rules were agreed upon:

1. **Generic utility functions** (e.g. array reversal with no domain logic): mark **Y** if
   the attribution comment is present and plausible. The code style alone is not sufficient to reject.
2. **Attribution-only** files (keyword in comment only, no other AI indicators): mark **U**,
   not N. Flag for later review.
3. **Mixed files** (AI-generated function + human wrapper `main()`): mark **Y** if the
   attributed function is the primary content (>50% LOC).
4. **Off-topic files** (e.g. web scraping code attributed to copilot but with no security CWE):
   mark **Y** — off-topic does not mean not AI-generated.

---

## Round 2 — Full Rating (Day 4)

**Target:** All 3,578 stage1=PASSED files  
**Assignment:** Each rater independently rates 1,789 files (split by file_id parity)

### Results

| Metric | Value |
|--------|-------|
| Total jointly rated | — |
| Agreement rate | — |
| Cohen's κ | — |
| κ target | ≥ 0.70 |

> Run: `python scripts/kappa.py`

### Post-Rating Actions

- Files with `stage2 = DISPUTED`: reviewed jointly and resolved manually.
- Files with `stage2 = RATER_REJECTED`: excluded from final corpus.
- `apply_stage2.py` run after resolution.

---

## Cohen's κ Formula Reference

```
κ = (P_o - P_e) / (1 - P_e)

P_o = observed agreement = (Y-Y + N-N + U-U) / total
P_e = expected agreement by chance
    = (P(A=Y)*P(B=Y)) + (P(A=N)*P(B=N)) + (P(A=U)*P(B=U))
```

Run: `python scripts/kappa.py` to compute automatically.

---

## Notes

- Rating sessions were conducted independently; raters did not discuss files before recording decisions.
- Files in the calibration batch (Round 1) are excluded from the final study corpus.
- All raw decisions are stored in `rater_decisions` table in `corpus.db`.
- Export: `python scripts/rater_tool.py export`
