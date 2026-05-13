# 🛡️ SupplyShield

**Explainable Multi-Modal Machine Learning for Detecting Malicious Python Packages in PyPI**

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![XGBoost](https://img.shields.io/badge/Model-XGBoost-orange.svg)](https://xgboost.readthedocs.io/)

SupplyShield is a real-time, explainable security scanner for PyPI packages. It combines three detection modalities — **metadata analysis**, **AST-based static code analysis**, and **stylometric consistency checking** — to detect malicious packages before installation and explain *why* they are suspicious using SHAP-driven attack taxonomy mapping.

---

## Key Results

| Metric | Value |
|--------|-------|
| **F1-Macro** | 0.9993 |
| **ROC-AUC** | 1.0000 |
| **False Positive Rate** | ≈ 0.0% |
| **Scan Time** | < 6 seconds per package |
| **Dataset** | 18,542 packages (10,565 malicious + 7,977 benign) |
| **Features** | 74 across 3 modalities |
| **Attack Vectors** | 7 Ladisa taxonomy categories with MITRE ATT&CK mapping |

---

## Quick Start

### 1. Install

```bash
git clone https://github.com/sarowar-ccny/supplyshield.git
cd supplyshield
pip install -r requirements.txt
```

### 2. Scan a Package

```bash
# Scan a single package
python src/cli/supplyshield.py scan requests

# Scan a suspicious package
python src/cli/supplyshield.py scan requesra

# JSON output
python src/cli/supplyshield.py scan flask --json

# Verbose mode (show SHAP features for clean packages too)
python src/cli/supplyshield.py scan colorama --verbose
```

### 3. Batch Scan

```bash
echo -e "requests\nflask\nnumpy\ncolorama" > packages.txt
python src/cli/supplyshield.py batch packages.txt --output results.json
```

### 4. Live Monitoring (Scan New PyPI Uploads)

```bash
# One-time scan of 40 most recent PyPI packages
python src/cli/supplyshield_monitor.py scan --count 40 --report

# Continuous monitoring (every 5 minutes)
python src/cli/supplyshield_monitor.py monitor --interval 300

# View alert history
python src/cli/supplyshield_monitor.py history
```

### 5. Safe Install (Pre-Install Security Gate)

```bash
# Instead of pip install, use:
python src/cli/supplyshield_install.py requests flask

# Scan only, don't install
python src/cli/supplyshield_install.py some-package --scan-only
```

### 6. Web Interface

```bash
streamlit run app.py
# Opens browser at http://localhost:8501
```

---

## Three-Tier Detection Architecture

```
supplyshield scan <package>
  │
  ├─ Tier 1: Metadata (21 features) ─── Always available via PyPI API
  │   Author reputation, naming patterns, documentation quality
  │
  ├─ Tier 2: Static Code (45 features) ─── When source distribution exists
  │   AST parsing: exec calls, network ops, obfuscation, data harvesting
  │
  ├─ Tier 3: Stylometric (8 features) ─── When multi-file package
  │   Intra-package coding style variance for trojanization detection
  │
  ├─ XGBoost Classifier → malicious probability
  ├─ SHAP TreeExplainer → per-feature attribution
  ├─ Two-Layer Taxonomy Mapping → Ladisa attack vector classification
  └─ Risk Assessment with MITRE ATT&CK mapping
```

---

## Attack Taxonomy (7 Vectors)

| Code | Attack Type | MITRE ATT&CK | Detection Layer |
|------|------------|---------------|-----------------|
| AV-001 | Typosquatting | T1195.002 | Metadata (name analysis) |
| AV-002 | Install-Hook Exploitation | T1059.006 | Static Code (setup.py) |
| AV-003 | Data Exfiltration | T1005+T1041 | Static Code (subprocess + network) |
| AV-004 | Obfuscated Payload | T1027 | Static Code (base64 + entropy) |
| AV-005 | Sparse Identity | T1036 | Metadata (systemic absence) |
| AV-006 | Backdoor / Remote Access | T1059+T1105 | Static Code (exec + obfusc + network) |
| AV-007 | Trojanized Package | T1195.001 | Stylometric (style variance) |

---

## Project Structure

```
supplyshield/
├── app.py                              # Streamlit web interface
├── requirements.txt
├── README.md
├── src/
│   ├── cli/
│   │   ├── supplyshield.py             # Single package scanner (1,066 lines)
│   │   ├── supplyshield_monitor.py     # Live PyPI monitoring (756 lines)
│   │   └── supplyshield_install.py     # pip install interceptor (312 lines)
│   ├── features/
│   │   ├── extract_features_v2.py      # Three-tier feature extraction
│   │   └── extract_stylometric.py      # Modality C: stylometric features
│   ├── classifier/
│   │   └── train_baselines.py          # XGBoost, RF, SVM, MLP training
│   └── evaluation/
│       ├── ablation_study.py           # 5-fold CV ablation (v1)
│       ├── ablation_study_v2.py        # Stylometric impact ablation (v2)
│       ├── taxonomy_mapper.py          # SHAP + Ladisa taxonomy mapping
│       ├── generate_data_quality_report.py
│       └── generate_eda_report.py
├── data/
│   └── models/
│       ├── xgboost_v2.json             # Trained XGBoost model
│       └── feature_cols_v2.json        # Feature column order
└── outputs/
    ├── figures/                        # Thesis figures
    ├── reports/                        # Generated reports
    └── threat_intel/                   # Live monitoring results
```

---

## Contributions

1. **Defense-in-Depth Multi-Modal Fusion:** Metadata catches 85% of attacks, code analysis catches 15% — complementary coverage, not marginal improvement.

2. **Explainable Taxonomy Mapping:** First system mapping SHAP attributions to the Ladisa et al. (IEEE S&P 2023) taxonomy with MITRE ATT&CK IDs.

3. **Stylometric Trojanization Detection:** First application of intra-package code stylometry (Caliskan-Islam et al., NDSS 2015) to supply chain defense. 96.3% AUC with 8 features alone.

4. **Practical Real-Time Deployment:** Working CLI + live monitoring + web interface. Three-tier graceful degradation. 0.49s/package throughput.

---

## Citation

```bibtex
@thesis{zahan2026supplyshield,
  author  = {MD Sarowar Zahan},
  title   = {SupplyShield: Explainable Multi-Modal Machine Learning for
             Detecting Malicious Python Packages in PyPI},
  school  = {The City College of New York},
  year    = {2026},
  type    = {Course Project},
  note    = {EE I7600: AI in Cybersecurity, Spring 2026}
}
```

---

## References

- Ladisa et al. (2023) "SoK: Taxonomy of Attacks on OSS Supply Chains." IEEE S&P 2023
- Lundberg & Lee (2017) "A Unified Approach to Interpreting Model Predictions." NeurIPS 2017
- Grinsztajn et al. (2022) "Why do tree-based models still outperform deep learning on tabular data?" NeurIPS 2022
- Caliskan-Islam et al. (2015) "De-anonymizing Programmers via Code Stylometry." NDSS 2015
- Gao et al. (2025) "MALGUARD: Detecting Malicious PyPI Packages." USENIX Security 2025

---

## License

MIT License. See [LICENSE](LICENSE) for details.


