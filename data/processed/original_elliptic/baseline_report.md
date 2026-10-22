# Original Elliptic Dataset - Random Forest Baseline Report

> **SIH26183 Domain Warning:** This model classifies individual Bitcoin transactions as illicit vs. licit.
> It **does NOT identify cryptocurrency exchanges**. In original Elliptic, licit transactions include verified exchanges.
> Exchange attribution requires separate entity clustering and verified deposit-address attribution databases.

## 1. Setup & Configuration

- **Model:** Random Forest (`n_estimators=100`, `class_weight='balanced'`, `max_depth=None`)
- **Dataset Split:** Train (timesteps 1–34), Validation (timesteps 35–39), Test (timesteps 40–49)
- **Supervised Target:** Class 1 (Illicit) = 1, Class 2 (Licit) = 0. Unknown transactions excluded.
- **Evaluated Timestamp:** 2026-10-17T19:53:32.574832+00:00

## 2. Overall Performance Summary

| Split | Illicit Precision | Illicit Recall | Illicit F1 | Licit F1 | Macro F1 | ROC-AUC | PR-AUC |
|---|---|---|---|---|---|---|---|
| **TRAIN** | 0.9986 | 1.0000 | 0.9993 | 0.9999 | 0.9996 | 1.0000 | 1.0000 |
| **VAL** | 0.9402 | 0.9150 | 0.9274 | 0.9937 | 0.9605 | 0.9895 | 0.9561 |
| **TEST** | 0.8724 | 0.5912 | 0.7048 | 0.9852 | 0.8450 | 0.8890 | 0.6673 |

## 3. Confusion Matrices

### Validation Split (Time Steps 35–39)

| | Predicted Licit (0) | Predicted Illicit (1) | Total |
|---|---|---|---|
| **Actual Licit (0)** | 5013 (TN) | 26 (FP) | 5039 |
| **Actual Illicit (1)** | 38 (FN) | 409 (TP) | 447 |

### Test Split (Time Steps 40–49)

| | Predicted Licit (0) | Predicted Illicit (1) | Total |
|---|---|---|---|
| **Actual Licit (0)** | 10493 (TN) | 55 (FP) | 10548 |
| **Actual Illicit (1)** | 260 (FN) | 376 (TP) | 636 |

## 4. Temporal Drift & Timestep-by-Timestep Analysis

The Elliptic dataset exhibits a well-documented temporal shift around time step 43 (coinciding with the shutdown of a major darknet marketplace).
Below is the breakdown of illicit transaction performance across evaluation time steps:

| Time Step | Total | Illicit Count | Illicit % | Precision | Recall | F1-Score |
|---|---|---|---|---|---|---|
| 35 | 1341 | 182 | 13.57% | 0.9620 | 0.9725 | 0.9672 |
| 36 | 1708 | 33 | 1.93% | 0.7949 | 0.9394 | 0.8611 |
| 37 | 498 | 40 | 8.03% | 0.9630 | 0.6500 | 0.7761 |
| 38 | 756 | 111 | 14.68% | 0.9901 | 0.9009 | 0.9434 |
| 39 | 1183 | 81 | 6.85% | 0.8929 | 0.9259 | 0.9091 |
| 40 | 1211 | 112 | 9.25% | 0.9375 | 0.6696 | 0.7812 |
| 41 | 1132 | 116 | 10.25% | 0.9643 | 0.9310 | 0.9474 |
| 42 | 2154 | 239 | 11.10% | 0.9645 | 0.7950 | 0.8716 |
| 43 | 1370 | 24 | 1.75% | 0.0000 | 0.0000 | 0.0000 |
| 44 | 1591 | 24 | 1.51% | 0.0588 | 0.0417 | 0.0488 |
| 45 | 1221 | 5 | 0.41% | 0.0000 | 0.0000 | 0.0000 |
| 46 | 712 | 2 | 0.28% | 0.1429 | 0.5000 | 0.2222 |
| 47 | 846 | 22 | 2.60% | 0.0000 | 0.0000 | 0.0000 |
| 48 | 471 | 36 | 7.64% | 0.0000 | 0.0000 | 0.0000 |
| 49 | 476 | 56 | 11.76% | 0.5000 | 0.0179 | 0.0345 |

## 5. Summary & Key Takeaways

1. **Validation Performance:** High precision (94.0%) and recall (91.5%) on immediate subsequent time steps (35–39).
2. **Distribution Shift on Test:** On time steps 40–49, illicit precision remains high (87.2%), while recall drops to ~59.1% (F1 = 70.5%). This replicates the exact baseline behavior reported in Weber et al. (2019) due to topological shifts in illicit money flows.
3. **Graph & Temporal Leakage:** Rigorous edge and partition audits confirm zero cross-timestep edges and zero ID overlap between splits.
