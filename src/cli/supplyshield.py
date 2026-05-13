#!/usr/bin/env python3
"""
SupplyShield CLI — Real-Time Pre-Install PyPI Package Scanner
================================================================
Three-tier detection architecture:
  Tier 1: Metadata interrogation (always available)
  Tier 2: Static code analysis (when source distribution available)
  Tier 3: Stylometric consistency (when multi-file package)

Usage:
  supplyshield scan <package_name>
  supplyshield scan <package_name> --version 1.2.3
  supplyshield scan <package_name> --json
  supplyshield scan <package_name> --verbose

Examples:
  python src/cli/supplyshield.py scan requests
  python src/cli/supplyshield.py scan requesra
  python src/cli/supplyshield.py scan colorama --json
  python src/cli/supplyshield.py batch packages.txt --output results.json

Output:
  Formatted risk assessment with:
  - Risk level (CLEAN / LOW / MEDIUM / HIGH / CRITICAL)
  - Modalities evaluated (Metadata ✓/✗, Code ✓/✗, Stylometric ✓/✗)
  - Attack vector classification (Ladisa taxonomy AV-001 to AV-007)
  - MITRE ATT&CK mapping
  - Top contributing features with SHAP values
  - Natural language explanation
  - Recommendation (install / review / reject)

Dependencies:
  pip install xgboost shap --break-system-packages


"""

import json
import os
import sys
import ast
import re
import math
import time
import shutil
import tarfile
import zipfile
import tempfile
import pickle
import warnings
import argparse
import logging
from datetime import datetime, timezone
from pathlib import Path
from collections import Counter, defaultdict

warnings.filterwarnings("ignore")

# ============================================================================
# PATH CONFIGURATION
# ============================================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
MODEL_PATH = PROJECT_ROOT / "data" / "models" / "xgboost_v2.json"
SCALER_PATH = PROJECT_ROOT / "data" / "models" / "scaler_v2.pkl"
FEATURE_COLS_PATH = PROJECT_ROOT / "data" / "models" / "feature_cols_v2.json"
TOP_PACKAGES_PATH = PROJECT_ROOT / "data" / "benign" / "top_pypi_packages.json"

PYPI_API = "https://pypi.org/pypi/{}/json"
PYPI_API_VERSION = "https://pypi.org/pypi/{}/{}/json"

# ============================================================================
# ATTACK TAXONOMY
# ============================================================================

ATTACK_TAXONOMY = {
    "AV-001": {"name": "Typosquatting", "severity": "HIGH",
               "mitre": "T1195.002", "color": "\033[93m"},
    "AV-002": {"name": "Install-Hook Exploitation", "severity": "CRITICAL",
               "mitre": "T1059.006", "color": "\033[91m"},
    "AV-003": {"name": "Data Exfiltration", "severity": "CRITICAL",
               "mitre": "T1005+T1041", "color": "\033[91m"},
    "AV-004": {"name": "Obfuscated Payload", "severity": "HIGH",
               "mitre": "T1027", "color": "\033[93m"},
    "AV-005": {"name": "Sparse Identity", "severity": "MEDIUM",
               "mitre": "T1036", "color": "\033[33m"},
    "AV-006": {"name": "Backdoor / Remote Access", "severity": "CRITICAL",
               "mitre": "T1059+T1105", "color": "\033[91m"},
    "AV-007": {"name": "Trojanized Package", "severity": "CRITICAL",
               "mitre": "T1195.001", "color": "\033[91m"},
    "AV-000": {"name": "No Attack Detected", "severity": "NONE",
               "mitre": "N/A", "color": "\033[92m"},
}

FEATURE_DESCRIPTIONS = {
    "homepage_present": "project homepage URL",
    "M14_has_classifiers": "PyPI trove classifiers",
    "author_email_present": "author email address",
    "has_license": "license specification",
    "M3_author_account_age_days": "author account age",
    "M1_min_edit_distance": "name similarity to popular packages",
    "M10_readme_length": "README/description length",
    "M7_version_count": "released versions",
    "M13_file_count": "distribution file count",
    "M15_publish_hour_utc": "publication time pattern",
    "has_subprocess": "subprocess module usage",
    "has_eval": "eval() function usage",
    "has_exec": "exec() function usage",
    "has_base64": "base64 module usage",
    "has_socket": "socket module usage",
    "has_requests": "HTTP requests library",
    "S9_avg_string_entropy": "string obfuscation level",
    "S11_env_var_access_count": "environment variable access",
    "S12_sensitive_path_access": "credential file access (.ssh, .aws)",
    "S20_webhook_url_count": "Discord/Telegram webhook URLs",
    "STY1_naming_convention_variance": "coding style inconsistency (naming)",
    "STY5_comment_density_variance": "comment pattern inconsistency",
}

# ANSI colors
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


# ============================================================================
# TOP PACKAGES LOADER
# ============================================================================

TOP_100_FALLBACK = [
    "boto3", "botocore", "urllib3", "requests", "setuptools", "certifi",
    "charset-normalizer", "idna", "pip", "python-dateutil", "typing-extensions",
    "numpy", "six", "cryptography", "pyyaml", "packaging", "jinja2",
    "colorama", "wheel", "click", "pandas", "pillow", "scipy",
    "flask", "django", "sqlalchemy", "matplotlib", "scikit-learn",
    "tensorflow", "torch", "beautifulsoup4", "lxml", "openpyxl",
    "psutil", "tqdm", "rich", "httpx", "fastapi", "pydantic",
]

def load_top_packages():
    if TOP_PACKAGES_PATH.exists():
        try:
            with open(TOP_PACKAGES_PATH) as f:
                data = json.load(f)
            if isinstance(data, list):
                return data[:5000] if isinstance(data[0], str) else [d.get("project", "") for d in data[:5000]]
            elif isinstance(data, dict) and "rows" in data:
                return [r["project"] for r in data["rows"][:5000]]
        except Exception:
            pass
    return TOP_100_FALLBACK


# ============================================================================
# FEATURE EXTRACTION
# ============================================================================

def levenshtein(s1, s2):
    if len(s1) < len(s2):
        return levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (c1 != c2)))
        prev = curr
    return prev[-1]


def shannon_entropy(s):
    if not s or len(s) < 2:
        return 0.0
    freq = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values() if c > 0)


def extract_metadata_features(pkg_name, pypi_data, top_packages):
    """Extract Modality A: Metadata features."""
    features = {}

    if pypi_data is None:
        # Package not on PyPI — fill defaults
        features.update({
            "homepage_present": 0, "has_license": 0, "M14_has_classifiers": 0,
            "num_classifiers": 0, "author_email_present": 0,
            "M3_author_account_age_days": -1, "M7_version_count": 0,
            "M10_readme_length": 0, "M13_file_count": 0,
            "M9_has_documentation_url": 0, "M15_publish_hour_utc": -1,
            "num_dependencies": 0, "maintainer_count": 1,
            "days_since_last_release": 0, "name_length": len(pkg_name),
            "name_has_digits": 1 if any(c.isdigit() for c in pkg_name) else 0,
            "M4_author_total_packages": -1, "M5_author_total_downloads": -1,
        })
    else:
        info = pypi_data.get("info", {})
        releases = pypi_data.get("releases", {})
        urls = pypi_data.get("urls", [])

        features["homepage_present"] = 1 if (info.get("home_page") or
            (info.get("project_urls") or {}).get("Homepage")) else 0
        features["has_license"] = 1 if (info.get("license") or "").strip() else 0
        classifiers = info.get("classifiers", [])
        features["M14_has_classifiers"] = 1 if classifiers else 0
        features["num_classifiers"] = len(classifiers)
        features["author_email_present"] = 1 if (info.get("author_email") or "").strip() else 0
        features["M7_version_count"] = len(releases)
        features["M10_readme_length"] = len(info.get("description", "") or "")
        features["M13_file_count"] = len(urls)
        features["M9_has_documentation_url"] = 1 if info.get("docs_url") else 0
        features["num_dependencies"] = len(info.get("requires_dist") or [])
        features["maintainer_count"] = 1
        features["name_length"] = len(pkg_name)
        features["name_has_digits"] = 1 if any(c.isdigit() for c in pkg_name) else 0
        features["M4_author_total_packages"] = 0  # sentinel
        features["M5_author_total_downloads"] = 0

        # Author account age
        earliest = None
        latest = None
        for ver, files in releases.items():
            for f in files:
                ut = f.get("upload_time_iso_8601") or f.get("upload_time")
                if ut:
                    try:
                        dt = datetime.fromisoformat(ut.replace("Z", "+00:00"))
                        if earliest is None or dt < earliest:
                            earliest = dt
                        if latest is None or dt > latest:
                            latest = dt
                    except Exception:
                        pass
        now = datetime.now(timezone.utc)
        features["M3_author_account_age_days"] = (now - earliest).days if earliest else -1
        features["M15_publish_hour_utc"] = latest.hour if latest else -1
        features["days_since_last_release"] = (now - latest).days if latest else 0

    # Typosquatting analysis
    pkg_lower = pkg_name.lower().replace("-", "_").replace(".", "_")
    min_dist = 99
    closest = ""
    for top in top_packages[:2000]:
        top_lower = top.lower().replace("-", "_").replace(".", "_")
        if pkg_lower == top_lower:
            min_dist = 0
            closest = top
            break
        if abs(len(pkg_lower) - len(top_lower)) > 3:
            continue
        d = levenshtein(pkg_lower, top_lower)
        if d < min_dist:
            min_dist = d
            closest = top

    features["M1_min_edit_distance"] = min_dist
    features["M2_name_length_ratio"] = round(len(pkg_name) / max(len(closest), 1), 4) if closest else 1.0
    features["name_typosquat_score"] = round(1.0 - min_dist / max(len(pkg_name), 1), 4) if min_dist < len(pkg_name) else 0.0

    return features, closest


def extract_static_features(source_dir):
    """Extract Modality B: Static code analysis features."""
    features = {k: 0 for k in [
        "has_eval", "has_exec", "has_subprocess", "has_os_system", "has_base64",
        "has_socket", "has_requests", "has_ctypes", "has_pkg_resources",
        "has_install_script", "setup_py_obfuscated", "num_functions", "num_imports",
        "avg_function_length", "max_function_length", "api_risk_score",
        "S1_setup_py_exec_count", "S2_has_cmdclass_override", "S3_init_py_exec_count",
        "S4_total_eval_exec_calls", "S5_total_subprocess_calls", "S6_total_network_calls",
        "S7_hardcoded_url_count", "S8_base64_decode_count", "S9_avg_string_entropy",
        "S11_env_var_access_count", "S12_sensitive_path_access", "S13_file_write_count",
        "S14_code_to_comment_ratio", "S15_ast_parse_failure_rate",
        "S16_xor_operation_count", "S17_hex_encoded_strings", "S18_dynamic_import_count",
        "S19_fernet_usage", "S20_webhook_url_count", "S21_platform_check_count",
        "S22_ast_max_depth", "S23_cyclomatic_complexity", "S24_obfuscated_variable_ratio",
        "S25_string_concat_count", "S26_sleep_call_count", "S27_temp_file_operations",
        "S28_dns_lookup_count", "S29_zip_archive_operations", "S30_code_line_count",
    ]}

    SENSITIVE_PATHS = [".ssh", ".aws", ".npmrc", ".env", "id_rsa", "Login Data", "logins.json"]
    WEBHOOK_PATTERNS = [r"discord(?:app)?\.com/api/webhooks", r"api\.telegram\.org/bot", r"hooks\.slack\.com"]
    URL_PATTERN = re.compile(r'https?://[^\s\'"\\)>\]}{,]+|\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')

    py_files = list(Path(source_dir).rglob("*.py"))
    if not py_files:
        return features

    total_files = len(py_files)
    parse_failures = 0
    all_entropies = []
    code_lines = 0
    comment_lines = 0
    total_vars = 0
    short_vars = 0
    max_depth = 0
    total_funcs = 0
    func_lengths = []
    total_imports = 0

    exec_names = {"eval", "exec", "compile"}
    sub_names = {"Popen", "run", "call", "check_output", "system", "popen"}

    for py_file in py_files:
        try:
            source = py_file.read_text(encoding="utf-8", errors="replace")
        except Exception:
            parse_failures += 1
            continue

        fname = py_file.name.lower()
        is_setup = fname in ("setup.py", "setup.cfg")
        is_init = fname == "__init__.py"
        lines = source.split("\n")

        for line in lines:
            s = line.strip()
            if s.startswith("#"):
                comment_lines += 1
            elif s:
                code_lines += 1

        features["S30_code_line_count"] += len(lines)

        # Binary module detection
        if "import subprocess" in source or "from subprocess" in source:
            features["has_subprocess"] = 1
        if "import base64" in source or "from base64" in source:
            features["has_base64"] = 1
        if "import socket" in source or "from socket" in source:
            features["has_socket"] = 1
        if "import requests" in source or "from requests" in source:
            features["has_requests"] = 1
        if "os.system" in source:
            features["has_os_system"] = 1
        if "import ctypes" in source:
            features["has_ctypes"] = 1
        if "pkg_resources" in source:
            features["has_pkg_resources"] = 1

        try:
            tree = ast.parse(source)
        except SyntaxError:
            parse_failures += 1
            continue

        # AST depth
        depth = _ast_depth(tree)
        if depth > max_depth:
            max_depth = depth

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = _call_name(node)
                if func_name in exec_names:
                    features["S4_total_eval_exec_calls"] += 1
                    features["has_eval"] = 1
                    if is_setup:
                        features["S1_setup_py_exec_count"] += 1
                    if is_init:
                        features["S3_init_py_exec_count"] += 1
                if func_name in sub_names or (func_name and "subprocess" in func_name):
                    features["S5_total_subprocess_calls"] += 1
                if func_name and any(n in func_name for n in ["urlopen", "requests.", "http.", "socket."]):
                    features["S6_total_network_calls"] += 1
                if func_name and "b64decode" in func_name:
                    features["S8_base64_decode_count"] += 1
                if func_name and ("getenv" in func_name or "os.environ" in func_name):
                    features["S11_env_var_access_count"] += 1
                if func_name and ("__import__" in func_name or "import_module" in func_name):
                    features["S18_dynamic_import_count"] += 1
                if func_name and "Fernet" in func_name:
                    features["S19_fernet_usage"] += 1
                if func_name and "sleep" in func_name:
                    features["S26_sleep_call_count"] += 1
                if func_name and func_name in ("open", "write"):
                    features["S13_file_write_count"] += 1
                if func_name and ("tempfile" in func_name or "mkstemp" in func_name):
                    features["S27_temp_file_operations"] += 1
                if func_name and ("ZipFile" in func_name or "tarfile" in func_name):
                    features["S29_zip_archive_operations"] += 1
                if func_name and ("getaddrinfo" in func_name or "gethostbyname" in func_name):
                    features["S28_dns_lookup_count"] += 1

            if isinstance(node, ast.keyword) and is_setup:
                if getattr(node, "arg", "") == "cmdclass":
                    features["S2_has_cmdclass_override"] = 1
            if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitXor):
                features["S16_xor_operation_count"] += 1
            if isinstance(node, ast.Attribute):
                attr = _attr_string(node)
                if attr and any(p in attr for p in ["sys.platform", "platform.system", "os.name"]):
                    features["S21_platform_check_count"] += 1
                if attr and "os.environ" in attr:
                    features["S11_env_var_access_count"] += 1
            if isinstance(node, ast.Name):
                total_vars += 1
                if len(node.id) <= 2 and node.id not in ("i", "j", "k", "x", "y", "f", "e", "_"):
                    short_vars += 1
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                s = node.value
                if len(s) > 20:
                    all_entropies.append(shannon_entropy(s))
                for sp in SENSITIVE_PATHS:
                    if sp.lower() in s.lower():
                        features["S12_sensitive_path_access"] += 1
                        break
                if re.match(r'^[0-9a-fA-F]{20,}$', s):
                    features["S17_hex_encoded_strings"] += 1
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                total_funcs += 1
                total_imports += len([n for n in ast.walk(node) if isinstance(n, (ast.Import, ast.ImportFrom))])
                if hasattr(node, "end_lineno") and hasattr(node, "lineno"):
                    func_lengths.append(node.end_lineno - node.lineno + 1)
            if isinstance(node, (ast.If, ast.While, ast.For, ast.ExceptHandler)):
                features["S23_cyclomatic_complexity"] += 1

        features["S7_hardcoded_url_count"] += len(URL_PATTERN.findall(source))
        for wp in WEBHOOK_PATTERNS:
            features["S20_webhook_url_count"] += len(re.findall(wp, source, re.I))

    features["S22_ast_max_depth"] = max_depth
    if all_entropies:
        features["S9_avg_string_entropy"] = round(sum(all_entropies) / len(all_entropies), 4)
    if comment_lines > 0:
        features["S14_code_to_comment_ratio"] = round(code_lines / comment_lines, 4)
    else:
        features["S14_code_to_comment_ratio"] = float(code_lines)
    features["S15_ast_parse_failure_rate"] = round(parse_failures / max(total_files, 1), 4)
    if total_vars > 0:
        features["S24_obfuscated_variable_ratio"] = round(short_vars / total_vars, 4)
    features["num_functions"] = total_funcs
    features["num_imports"] = total_imports
    if func_lengths:
        features["avg_function_length"] = round(sum(func_lengths) / len(func_lengths), 4)
        features["max_function_length"] = max(func_lengths)
    features["has_install_script"] = 1 if any(f.name == "setup.py" for f in py_files) else 0

    # API risk score
    risky = features["S4_total_eval_exec_calls"] + features["S5_total_subprocess_calls"] + features["S6_total_network_calls"]
    features["api_risk_score"] = round(risky / max(total_files, 1), 4)

    return features


def extract_stylometric_features(source_dir):
    """Extract Modality C: Stylometric consistency features."""
    features = {f"STY{i}_{n}": 0.0 for i, n in enumerate([
        "naming_convention_variance", "indentation_consistency",
        "line_length_variance", "function_length_variance",
        "comment_density_variance", "ast_depth_variance",
        "vocabulary_richness", "import_style_consistency",
    ], 1)}

    py_files = list(Path(source_dir).rglob("*.py"))
    if len(py_files) < 2:
        return features, False

    per_file = []
    all_ids = []
    all_imports = []

    for pf in py_files:
        try:
            src = pf.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(src)
        except Exception:
            continue

        lines = src.split("\n")
        stat = {}

        # Naming
        names = [n.id for n in ast.walk(tree) if isinstance(n, ast.Name)]
        all_ids.extend(names)
        if names:
            snake = sum(1 for n in names if "_" in n and n.lower() == n)
            camel = sum(1 for n in names if "_" not in n and len(n) > 1 and n[0].islower() and any(c.isupper() for c in n[1:]))
            total = snake + camel
            stat["snake_ratio"] = snake / total if total > 0 else 0.5

        # Line length
        ll = [len(l) for l in lines if l.strip()]
        if ll:
            stat["mean_line_len"] = sum(ll) / len(ll)

        # Function length
        fl = []
        for n in ast.walk(tree):
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if hasattr(n, "end_lineno"):
                    fl.append(n.end_lineno - n.lineno + 1)
        if fl:
            stat["mean_func_len"] = sum(fl) / len(fl)

        # Comment density
        code = sum(1 for l in lines if l.strip() and not l.strip().startswith("#"))
        comm = sum(1 for l in lines if l.strip().startswith("#"))
        if code + comm > 0:
            stat["comment_ratio"] = comm / (code + comm)

        # AST depth
        stat["ast_depth"] = _ast_depth(tree)

        # Imports
        for n in ast.walk(tree):
            if isinstance(n, ast.Import):
                all_imports.append(0)
            elif isinstance(n, ast.ImportFrom):
                all_imports.append(1)

        if stat:
            per_file.append(stat)

    if len(per_file) < 2:
        return features, False

    def _std(vals):
        if len(vals) < 2:
            return 0.0
        m = sum(vals) / len(vals)
        return math.sqrt(sum((x - m) ** 2 for x in vals) / (len(vals) - 1))

    sr = [s["snake_ratio"] for s in per_file if "snake_ratio" in s]
    if len(sr) >= 2:
        features["STY1_naming_convention_variance"] = round(_std(sr), 4)

    ll = [s["mean_line_len"] for s in per_file if "mean_line_len" in s]
    if len(ll) >= 2:
        features["STY3_line_length_variance"] = round(_std(ll), 4)

    fl = [s["mean_func_len"] for s in per_file if "mean_func_len" in s]
    if len(fl) >= 2:
        features["STY4_function_length_variance"] = round(_std(fl), 4)

    cr = [s["comment_ratio"] for s in per_file if "comment_ratio" in s]
    if len(cr) >= 2:
        features["STY5_comment_density_variance"] = round(_std(cr), 4)

    ad = [s["ast_depth"] for s in per_file if "ast_depth" in s]
    if len(ad) >= 2:
        features["STY6_ast_depth_variance"] = round(_std(ad), 4)

    if all_ids:
        features["STY7_vocabulary_richness"] = round(len(set(all_ids)) / len(all_ids), 4)

    if all_imports:
        p = sum(1 for s in all_imports if s == 0) / len(all_imports)
        if 0 < p < 1:
            features["STY8_import_style_consistency"] = round(-p * math.log2(p) - (1 - p) * math.log2(1 - p), 4)

    return features, True


def _ast_depth(node):
    max_d = 0
    stack = [(node, 0)]
    while stack:
        cur, d = stack.pop()
        if not isinstance(cur, ast.AST):
            continue
        if d > max_d:
            max_d = d
        if d < 100:
            try:
                for c in ast.iter_child_nodes(cur):
                    stack.append((c, d + 1))
            except Exception:
                pass
    return max_d


def _call_name(node):
    f = node.func
    if isinstance(f, ast.Name):
        return f.id
    if isinstance(f, ast.Attribute):
        return _attr_string(f)
    return ""


def _attr_string(node):
    parts = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    return ".".join(reversed(parts))


# ============================================================================
# TAXONOMY MAPPING
# ============================================================================

def classify_attack(features):
    """Compound pattern scoring for attack type classification."""
    any_exec = features.get("has_subprocess", 0) or features.get("has_os_system", 0) or features.get("S5_total_subprocess_calls", 0) > 0
    any_network = features.get("has_requests", 0) or features.get("has_socket", 0) or features.get("S6_total_network_calls", 0) > 0
    any_obfusc = features.get("has_base64", 0) or features.get("S8_base64_decode_count", 0) > 0 or features.get("S19_fernet_usage", 0) > 0
    any_eval = features.get("has_eval", 0) or features.get("has_exec", 0)
    has_code = any_exec or any_network or any_obfusc or any_eval

    scores = defaultdict(float)

    # AV-003: Data Exfiltration
    if any_exec and any_network:
        scores["AV-003"] += 5.0
    elif any_network:
        scores["AV-003"] += 3.0
    elif any_exec and any_obfusc:
        scores["AV-003"] += 2.5
    elif any_exec:
        scores["AV-003"] += 2.0
    elif any_eval:
        scores["AV-003"] += 1.5
    if features.get("S11_env_var_access_count", 0) > 0:
        scores["AV-003"] += 2.0
    if features.get("S12_sensitive_path_access", 0) > 0:
        scores["AV-003"] += 3.0
    if features.get("S20_webhook_url_count", 0) > 0:
        scores["AV-003"] += 3.0

    # AV-006: Backdoor
    if any_exec and any_obfusc and any_network:
        scores["AV-006"] += 4.0
    elif features.get("has_socket", 0) and any_exec:
        scores["AV-006"] += 3.5

    # AV-001: Typosquatting
    edit_dist = features.get("M1_min_edit_distance", 99)
    if 0 <= edit_dist <= 2:
        scores["AV-001"] += (3 - edit_dist) * 1.5
    if scores["AV-003"] > 0 or scores["AV-006"] > 0:
        scores["AV-001"] *= 0.5

    # AV-002: Install-hook
    if features.get("S2_has_cmdclass_override", 0) or features.get("S1_setup_py_exec_count", 0) > 0:
        scores["AV-002"] += 2.0
    if scores["AV-003"] > 2 or scores["AV-006"] > 2:
        scores["AV-002"] *= 0.3

    # AV-004: Obfuscation
    if any_obfusc and not any_network and not any_exec:
        scores["AV-004"] += 3.0
    if features.get("S9_avg_string_entropy", 0) > 4.5:
        scores["AV-004"] += 2.0

    # AV-005: Sparse identity
    sparse = sum([
        1 if features.get("homepage_present", 0) == 0 else 0,
        1 if features.get("has_license", 0) == 0 else 0,
        1 if features.get("M14_has_classifiers", 0) == 0 else 0,
        1 if features.get("author_email_present", 0) == 0 else 0,
    ])
    if sparse >= 3:
        scores["AV-005"] += sparse * 0.3

    # AV-007: Trojanized
    sty_variance = sum([
        features.get("STY1_naming_convention_variance", 0),
        features.get("STY5_comment_density_variance", 0),
        features.get("STY3_line_length_variance", 0) / 30 if features.get("STY3_line_length_variance", 0) > 0 else 0,
    ])
    if sty_variance > 0.5:
        scores["AV-007"] += sty_variance * 2.0

    behavioral = {k: v for k, v in scores.items() if k != "AV-005"}
    if behavioral and max(behavioral.values()) > 0:
        primary = max(behavioral, key=behavioral.get)
    elif scores:
        primary = max(scores, key=scores.get)
    else:
        primary = "AV-005" if sparse >= 3 else "AV-000"

    secondary = [k for k, v in sorted(scores.items(), key=lambda x: -x[1])
                 if k != primary and v > scores.get(primary, 0) * 0.3]

    return primary, secondary, dict(scores), has_code


# ============================================================================
# MODEL INFERENCE
# ============================================================================

def load_model():
    """Load trained XGBoost model, scaler, and feature columns."""
    import xgboost as xgb

    if not MODEL_PATH.exists():
        return None, None, None

    model = xgb.XGBClassifier()
    model.load_model(str(MODEL_PATH))

    scaler = None
    if SCALER_PATH.exists():
        with open(SCALER_PATH, "rb") as f:
            scaler = pickle.load(f)

    feature_cols = None
    if FEATURE_COLS_PATH.exists():
        with open(FEATURE_COLS_PATH) as f:
            feature_cols = json.load(f)

    return model, scaler, feature_cols


def predict(model, feature_cols, all_features):
    """Run model prediction and get probability."""
    feature_vector = []
    for col in feature_cols:
        val = all_features.get(col, 0)
        try:
            fval = float(val) if val is not None else 0.0
            if fval == -1:
                fval = 0.0
        except (ValueError, TypeError):
            fval = 0.0
        feature_vector.append(fval)

    import numpy as np
    X = np.array([feature_vector], dtype=np.float64)
    prob = model.predict_proba(X)[0][1]
    pred = 1 if prob >= 0.5 else 0
    return pred, float(prob), X


def compute_shap(model, X, feature_cols):
    """Compute SHAP values for the prediction."""
    try:
        import shap
        explainer = shap.TreeExplainer(model)
        shap_values = explainer.shap_values(X)
        top_indices = sorted(range(len(shap_values[0])),
                             key=lambda i: abs(shap_values[0][i]), reverse=True)[:10]
        top_features = []
        for idx in top_indices:
            top_features.append({
                "feature": feature_cols[idx],
                "shap_value": round(float(shap_values[0][idx]), 4),
                "description": FEATURE_DESCRIPTIONS.get(feature_cols[idx], feature_cols[idx]),
            })
        return top_features
    except Exception:
        return []


# ============================================================================
# PYPI API
# ============================================================================

def fetch_pypi(package_name, version=None):
    """Fetch package metadata from PyPI."""
    import urllib.request, urllib.error
    url = PYPI_API_VERSION.format(package_name, version) if version else PYPI_API.format(package_name)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "SupplyShield/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        return None
    except Exception:
        return None


def download_source(pypi_data):
    """Download and extract source distribution."""
    if pypi_data is None:
        return None
    urls = pypi_data.get("urls", [])
    sdist_url = None
    for u in urls:
        if u.get("packagetype") == "sdist":
            sdist_url = u.get("url")
            break
    if not sdist_url:
        for u in urls:
            if u.get("url", "").endswith(".tar.gz"):
                sdist_url = u.get("url")
                break
    if not sdist_url:
        return None

    import urllib.request
    tmp = tempfile.mkdtemp(prefix="ss_cli_")
    try:
        archive = os.path.join(tmp, "src.tar.gz")
        urllib.request.urlretrieve(sdist_url, archive)
        extract = os.path.join(tmp, "extracted")
        os.makedirs(extract)
        with tarfile.open(archive, "r:gz") as tf:
            tf.extractall(extract, filter="data")
        return extract
    except Exception:
        shutil.rmtree(tmp, ignore_errors=True)
        return None


# ============================================================================
# OUTPUT FORMATTING
# ============================================================================

def format_report(pkg_name, result, verbose=False):
    """Format the scan result as a colored terminal report."""
    lines = []
    w = lines.append

    risk = result["risk_level"]
    risk_colors = {"CLEAN": GREEN, "LOW": GREEN, "MEDIUM": YELLOW, "HIGH": YELLOW, "CRITICAL": RED}
    rc = risk_colors.get(risk, RESET)

    w(f"\n{BOLD}{'='*60}{RESET}")
    w(f"{BOLD} SupplyShield Risk Assessment: {CYAN}{pkg_name}{RESET}")
    w(f"{BOLD}{'='*60}{RESET}")

    w(f" Risk Level:     {rc}{BOLD}{risk}{RESET} (confidence: {result['confidence']:.1%})")

    # Modalities
    m_meta = f"{GREEN}Yes{RESET}" if result["modalities"]["metadata"] else f"{RED}No{RESET}"
    m_code = f"{GREEN}Yes{RESET}" if result["modalities"]["code"] else f"{DIM}No (source unavailable){RESET}"
    m_sty = f"{GREEN}Yes{RESET}" if result["modalities"]["stylometric"] else f"{DIM}No{RESET}"
    w(f" Modalities:     Metadata [{m_meta}]  Code [{m_code}]  Stylometric [{m_sty}]")

    if result["prediction"] == 1:
        av = result["attack_vector"]
        av_info = ATTACK_TAXONOMY.get(av, {})
        w(f"")
        w(f" {BOLD}Primary Attack:{RESET}  {av_info.get('color', '')}{av} \u2014 {av_info.get('name', 'Unknown')}{RESET}")
        w(f" Severity:       {av_info.get('severity', 'N/A')}")
        w(f" MITRE ATT&CK:  {av_info.get('mitre', 'N/A')}")

        if result.get("secondary_vectors"):
            sec = ", ".join([f"{v} ({ATTACK_TAXONOMY[v]['name']})" for v in result["secondary_vectors"][:3]])
            w(f" Secondary:      {sec}")

        if result.get("typosquat_target"):
            w(f" Typosquat of:   {YELLOW}{result['typosquat_target']}{RESET} "
              f"(edit distance: {result.get('edit_distance', '?')})")

        w(f"")
        w(f" {BOLD}Evidence:{RESET}")
        for feat in result.get("top_features", [])[:5]:
            desc = feat["description"]
            shap_val = feat["shap_value"]
            direction = f"{RED}suspicious{RESET}" if shap_val > 0 else f"{GREEN}absent/low{RESET}"
            w(f"   \u2022 {desc}: {direction} (SHAP: {shap_val:+.3f})")

        w(f"")
        w(f" {BOLD}{RED}Recommendation: DO NOT INSTALL.{RESET}")
    else:
        w(f"")
        w(f" {GREEN}Assessment: No indicators of malicious behavior.{RESET}")

        if verbose and result.get("top_features"):
            w(f"")
            w(f" {BOLD}Top Features:{RESET}")
            for feat in result["top_features"][:5]:
                w(f"   \u2022 {feat['description']}: SHAP {feat['shap_value']:+.3f}")

        w(f"")
        w(f" {GREEN}Recommendation: Safe to install.{RESET}")

    w(f"{BOLD}{'='*60}{RESET}")
    w(f" {DIM}Scan time: {result['scan_time']:.2f}s | SupplyShield v1.0{RESET}")
    w(f"")

    return "\n".join(lines)


def format_json(pkg_name, result):
    """Format result as JSON."""
    return json.dumps({
        "package": pkg_name,
        "version": result.get("version"),
        "risk_level": result["risk_level"],
        "confidence": result["confidence"],
        "prediction": "malicious" if result["prediction"] == 1 else "benign",
        "attack_vector": result.get("attack_vector", "AV-000"),
        "attack_name": ATTACK_TAXONOMY.get(result.get("attack_vector", "AV-000"), {}).get("name"),
        "severity": ATTACK_TAXONOMY.get(result.get("attack_vector", "AV-000"), {}).get("severity"),
        "mitre_attack": ATTACK_TAXONOMY.get(result.get("attack_vector", "AV-000"), {}).get("mitre"),
        "secondary_vectors": result.get("secondary_vectors", []),
        "modalities": result["modalities"],
        "top_features": result.get("top_features", []),
        "scan_time_sec": round(result["scan_time"], 3),
    }, indent=2)


# ============================================================================
# MAIN SCAN LOGIC
# ============================================================================

def scan_package(pkg_name, version=None, verbose=False):
    """Run the complete three-tier scan pipeline."""
    start_time = time.time()
    top_packages = load_top_packages()

    result = {
        "prediction": 0, "confidence": 0.0, "risk_level": "CLEAN",
        "modalities": {"metadata": False, "code": False, "stylometric": False},
        "attack_vector": "AV-000", "secondary_vectors": [],
        "top_features": [], "version": version,
    }

    # ── TIER 1: Metadata ──
    pypi_data = fetch_pypi(pkg_name, version)
    meta_features, closest_pkg = extract_metadata_features(pkg_name, pypi_data, top_packages)
    result["modalities"]["metadata"] = True

    all_features = dict(meta_features)

    if meta_features["M1_min_edit_distance"] <= 2 and meta_features["M1_min_edit_distance"] > 0:
        result["typosquat_target"] = closest_pkg
        result["edit_distance"] = meta_features["M1_min_edit_distance"]

    # ── TIER 2: Static Code Analysis ──
    source_dir = None
    try:
        source_dir = download_source(pypi_data)
        if source_dir:
            static_features = extract_static_features(source_dir)
            all_features.update(static_features)
            result["modalities"]["code"] = True

            # ── TIER 3: Stylometric Analysis ──
            sty_features, has_sty = extract_stylometric_features(source_dir)
            all_features.update(sty_features)
            if has_sty:
                result["modalities"]["stylometric"] = True
    except Exception:
        pass
    finally:
        if source_dir:
            shutil.rmtree(source_dir, ignore_errors=True)

    # ── MODEL PREDICTION ──
    model, scaler, feature_cols = load_model()

    if model is not None and feature_cols is not None:
        pred, prob, X = predict(model, feature_cols, all_features)
        result["prediction"] = pred
        result["confidence"] = prob

        if pred == 1:
            if prob >= 0.95:
                result["risk_level"] = "CRITICAL"
            elif prob >= 0.80:
                result["risk_level"] = "HIGH"
            elif prob >= 0.60:
                result["risk_level"] = "MEDIUM"
            else:
                result["risk_level"] = "LOW"

            # Attack classification
            primary, secondary, scores, _ = classify_attack(all_features)
            result["attack_vector"] = primary
            result["secondary_vectors"] = secondary

            # SHAP
            result["top_features"] = compute_shap(model, X, feature_cols)
        else:
            result["risk_level"] = "CLEAN"
            result["attack_vector"] = "AV-000"
            # Still compute SHAP for verbose mode
            if verbose:
                result["top_features"] = compute_shap(model, X, feature_cols)
    else:
        # Fallback: rule-based assessment without model
        sparse = sum([
            1 if all_features.get("homepage_present", 0) == 0 else 0,
            1 if all_features.get("has_license", 0) == 0 else 0,
            1 if all_features.get("M14_has_classifiers", 0) == 0 else 0,
        ])
        if pypi_data is None:
            result["risk_level"] = "HIGH"
            result["prediction"] = 1
            result["confidence"] = 0.8
            result["attack_vector"] = "AV-005"
        elif sparse >= 3:
            result["risk_level"] = "MEDIUM"
            result["prediction"] = 1
            result["confidence"] = 0.6
            result["attack_vector"] = "AV-005"

    result["scan_time"] = time.time() - start_time
    return result


# ============================================================================
# CLI ENTRY POINT
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        prog="supplyshield",
        description="SupplyShield: Real-time PyPI package security scanner",
    )
    subparsers = parser.add_subparsers(dest="command")

    # scan command
    scan_parser = subparsers.add_parser("scan", help="Scan a single package")
    scan_parser.add_argument("package", help="PyPI package name to scan")
    scan_parser.add_argument("--version", "-v", help="Specific version to scan")
    scan_parser.add_argument("--json", action="store_true", help="Output as JSON")
    scan_parser.add_argument("--verbose", action="store_true", help="Show detailed analysis")

    # batch command
    batch_parser = subparsers.add_parser("batch", help="Scan multiple packages")
    batch_parser.add_argument("file", help="File with package names (one per line)")
    batch_parser.add_argument("--output", "-o", default="scan_results.json", help="Output JSON file")

    args = parser.parse_args()

    if args.command == "scan":
        result = scan_package(args.package, args.version, args.verbose)
        if args.json:
            print(format_json(args.package, result))
        else:
            print(format_report(args.package, result, args.verbose))

    elif args.command == "batch":
        if not os.path.exists(args.file):
            print(f"Error: File not found: {args.file}")
            sys.exit(1)

        with open(args.file) as f:
            packages = [line.strip() for line in f if line.strip() and not line.startswith("#")]

        results = []
        for i, pkg in enumerate(packages, 1):
            print(f"[{i}/{len(packages)}] Scanning {pkg}...", end=" ", flush=True)
            result = scan_package(pkg)
            results.append({"package": pkg, **result})
            risk = result["risk_level"]
            rc = RED if risk in ("CRITICAL", "HIGH") else YELLOW if risk == "MEDIUM" else GREEN
            print(f"{rc}{risk}{RESET} ({result['scan_time']:.1f}s)")

        with open(args.output, "w") as f:
            json.dump(results, f, indent=2, default=str)
        print(f"\nResults saved to {args.output}")

        # Summary
        risk_counts = Counter(r["risk_level"] for r in results)
        print(f"\nSummary: {len(results)} packages scanned")
        for risk in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "CLEAN"]:
            if risk_counts.get(risk, 0) > 0:
                print(f"  {risk}: {risk_counts[risk]}")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
