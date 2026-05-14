# 🛡️ SupplyShield



**Explainable Multi-Modal Machine Learning for Detecting Malicious Python Packages in PyPI**

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![XGBoost](https://img.shields.io/badge/Model-XGBoost-orange.svg)](https://xgboost.readthedocs.io/)

**Explainable Multi-Modal Machine Learning for Detecting Malicious Python Packages in PyPI**

SupplyShield is a real-time, explainable security scanner for PyPI packages. It combines three detection modalities — **metadata analysis**, **AST-based static code analysis**, and **stylometric consistency checking** — to detect malicious packages before installation and explain *why* they are suspicious using SHAP-driven attack taxonomy mapping.

**Live Demo:** https://supplyshield-kpxgkzun4tzkji68nd56in.streamlit.app/ 

\---

## Key Results

|Metric|Value|
|-|-|
|**F1-Macro**|0.9993|
|**ROC-AUC**|1.0000|
|**False Positive Rate**|≈ 0.0%|
|**Scan Time**|< 6 seconds per package|
|**Dataset**|18,542 packages (10,565 malicious + 7,977 benign)|
|**Features**|74 across 3 modalities|
|**Attack Vectors**|7 Ladisa taxonomy categories with MITRE ATT\&CK mapping|

\---

## Quick Start

### 1\. Install

```bash
git clone https://github.com/sarowarzahan414/supplyshield.git
cd supplyshield
pip install -r requirements.txt
```

### 2\. Scan a Package

```bash
python src/cli/supplyshield.py scan requests           # Clean package
python src/cli/supplyshield.py scan requesra            # Typosquatting detected
python src/cli/supplyshield.py scan flask --json        # JSON output
python src/cli/supplyshield.py scan colorama --verbose  # Detailed SHAP analysis
```

### 3\. Batch Scan

```bash
echo -e "requests\\nflask\\nnumpy\\ncolorama" > packages.txt
python src/cli/supplyshield.py batch packages.txt --output results.json
```

### 4\. Live Monitoring (Scan New PyPI Uploads)

```bash
python src/cli/supplyshield\_monitor.py scan --count 40 --report
python src/cli/supplyshield\_monitor.py monitor --interval 300
python src/cli/supplyshield\_monitor.py history
```

### 5\. Safe Install (Pre-Install Security Gate)

```bash
python src/cli/supplyshield\_install.py requests flask        # Scans then installs
python src/cli/supplyshield\_install.py some-package --scan-only  # Scan without installing
```

### 6\. Web Interface

```bash
streamlit run app.py
```

\---

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
  └─ Risk Assessment with MITRE ATT\&CK mapping
```

\---

## Attack Taxonomy (7 Vectors)

|Code|Attack Type|MITRE ATT\&CK|Detection Layer|
|-|-|-|-|
|AV-001|Typosquatting|T1195.002|Metadata (name analysis)|
|AV-002|Install-Hook Exploitation|T1059.006|Static Code (setup.py)|
|AV-003|Data Exfiltration|T1005+T1041|Static Code (subprocess + network)|
|AV-004|Obfuscated Payload|T1027|Static Code (base64 + entropy)|
|AV-005|Sparse Identity|T1036|Metadata (systemic absence)|
|AV-006|Backdoor / Remote Access|T1059+T1105|Static Code (exec + obfusc + network)|
|AV-007|Trojanized Package|T1195.001|Stylometric (style variance)|

\---

## Project Structure

```
supplyshield/
├── app.py                              # Streamlit web interface
├── requirements.txt
├── README.md
├── CITATION.cff
├── LICENSE
├── src/
│   └── cli/
│       ├── supplyshield.py             # Single package scanner
│       ├── supplyshield\_monitor.py     # Live PyPI monitoring
│       └── supplyshield\_install.py     # pip install interceptor
└── data/
    └── models/
        ├── xgboost\_supplyshield.json   # Trained XGBoost model (74 features)
        └── feature\_cols.json           # Feature column order
```

\---

## Contributions

1. **Defense-in-Depth Multi-Modal Fusion:** Metadata catches 85% of attacks, code analysis catches 15% — complementary coverage, not marginal improvement.
2. **Explainable Taxonomy Mapping:** First system mapping SHAP attributions to the Ladisa et al. (IEEE S\&P 2023) taxonomy with MITRE ATT\&CK IDs.
3. **Stylometric Trojanization Detection:** First application of intra-package code stylometry (Caliskan-Islam et al., NDSS 2015) to supply chain defense. 96.3% AUC with 8 features alone.
4. **Practical Real-Time Deployment:** Working CLI + live monitoring + web interface. Three-tier graceful degradation. 0.49s/package throughput.

\---

## Citation

```bibtex
@thesis{zahan2026supplyshield,
  author  = {Md Sarowar Zahan},
  title   = {SupplyShield: Explainable Multi-Modal Machine Learning for
             Detecting Malicious Python Packages in PyPI},
  school  = {The City College of New York},
  year    = {2026},
  type    = {Course Project},
  note    = {EE I7600: AI in Cybersecurity, Spring 2026}
}
```

\---

## References

* Ladisa et al. (2023) "SoK: Taxonomy of Attacks on OSS Supply Chains." IEEE S\&P 2023
* Lundberg \& Lee (2017) "A Unified Approach to Interpreting Model Predictions." NeurIPS 2017
* Grinsztajn et al. (2022) "Why do tree-based models still outperform deep learning on tabular data?" NeurIPS 2022
* Caliskan-Islam et al. (2015) "De-anonymizing Programmers via Code Stylometry." NDSS 2015
* Gao et al. (2025) "MALGUARD: Detecting Malicious PyPI Packages." USENIX Security 2025

\---

## License

MIT License. See [LICENSE](LICENSE) for details.

**Author:** Md Sarowar Zahan | The City College of New York | Spring 2026

