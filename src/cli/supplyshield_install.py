#!/usr/bin/env python3
"""
SupplyShield Safe Install — Pre-Install Security Gate
=======================================================
Intercepts pip install commands and runs the SupplyShield three-tier
analysis BEFORE allowing installation. Blocks malicious packages,
warns on suspicious ones, and allows clean packages through.

Usage:
  # Instead of: pip install requests
  # Use:        supplyshield-install requests

  # Multiple packages:
  supplyshield-install flask requests colorama

  # With pip options (passed through after scan):
  supplyshield-install requests --upgrade

  # Force install even if flagged (expert override):
  supplyshield-install some-package --force

  # Scan only, don't install:
  supplyshield-install requests --scan-only

Setup (add to .bashrc or .zshrc for automatic interception):
  alias pip-install='python src/cli/supplyshield_install.py'
  # Or for full pip interception:
  # alias pip='python src/cli/supplyshield_install.py --pip-passthrough'

How it works:
  1. Parses the package name(s) from the command
  2. Runs SupplyShield three-tier scan on each package
  3. Decision gate:
     - CLEAN / LOW  → Proceeds with pip install automatically
     - MEDIUM       → Warns and asks for confirmation (Y/n)
     - HIGH         → Shows evidence, requires explicit --force to proceed
     - CRITICAL     → Blocks installation entirely (unless --force)
  4. If approved, executes the original pip install command


"""

import sys
import os
import subprocess
import argparse
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src" / "cli"))

from supplyshield import (
    scan_package, ATTACK_TAXONOMY, format_report,
)

# ANSI colors
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"
BG_RED = "\033[41m"
BG_YELLOW = "\033[43m"
BG_GREEN = "\033[42m"


def print_banner():
    print(f"""
{BOLD}{CYAN}╔══════════════════════════════════════════════════════╗
║         SupplyShield Safe Install v1.0               ║
║    Pre-Install Security Gate for PyPI Packages       ║
╚══════════════════════════════════════════════════════╝{RESET}
""")


def print_gate_decision(pkg_name, result):
    """Print the security gate decision with visual formatting."""
    risk = result["risk_level"]
    confidence = result["confidence"]
    scan_time = result["scan_time"]

    # Modality indicators
    m_meta = f"{GREEN}✓{RESET}" if result["modalities"]["metadata"] else f"{RED}✗{RESET}"
    m_code = f"{GREEN}✓{RESET}" if result["modalities"]["code"] else f"{DIM}✗{RESET}"
    m_sty = f"{GREEN}✓{RESET}" if result["modalities"]["stylometric"] else f"{DIM}✗{RESET}"
    mods = f"[Meta:{m_meta} Code:{m_code} Sty:{m_sty}]"

    if risk == "CLEAN":
        icon = f"{GREEN}✓ PASS{RESET}"
        bar_color = BG_GREEN
    elif risk == "LOW":
        icon = f"{GREEN}✓ PASS{RESET}"
        bar_color = BG_GREEN
    elif risk == "MEDIUM":
        icon = f"{YELLOW}⚠ WARN{RESET}"
        bar_color = BG_YELLOW
    elif risk == "HIGH":
        icon = f"{RED}✖ BLOCK{RESET}"
        bar_color = BG_RED
    else:  # CRITICAL
        icon = f"{RED}✖ BLOCK{RESET}"
        bar_color = BG_RED

    print(f"  {icon}  {BOLD}{pkg_name}{RESET}  →  {risk} ({confidence:.1%})  {mods}  [{scan_time:.1f}s]")

    # Show attack details for flagged packages
    if result["prediction"] == 1:
        av = result.get("attack_vector", "AV-000")
        av_info = ATTACK_TAXONOMY.get(av, {})
        print(f"         Attack: {av} — {av_info.get('name', 'Unknown')} "
              f"(MITRE: {av_info.get('mitre', 'N/A')})")

        if result.get("top_features"):
            print(f"         Evidence:")
            for feat in result["top_features"][:3]:
                desc = feat.get("description", feat["feature"])
                direction = "suspicious" if feat["shap_value"] > 0 else "absent/low"
                print(f"           • {desc}: {direction} (SHAP: {feat['shap_value']:+.3f})")

        if result.get("secondary_vectors"):
            sec = ", ".join([f"{v} ({ATTACK_TAXONOMY[v]['name']})"
                           for v in result["secondary_vectors"][:2]])
            print(f"         Secondary: {sec}")


def gate_decision(results, force=False):
    """
    Make the install/block decision based on scan results.

    Returns:
      - "proceed": safe to install
      - "confirm": ask user confirmation
      - "block":   block installation
      - "force":   blocked but user used --force
    """
    max_risk = "CLEAN"
    risk_order = {"CLEAN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

    for result in results:
        risk = result["risk_level"]
        if risk_order.get(risk, 0) > risk_order.get(max_risk, 0):
            max_risk = risk

    if max_risk in ("CLEAN", "LOW"):
        return "proceed"
    elif max_risk == "MEDIUM":
        return "confirm"
    elif force:
        return "force"
    else:
        return "block"


def ask_confirmation(pkg_names, max_risk):
    """Ask user whether to proceed with installation."""
    if max_risk == "MEDIUM":
        print(f"\n  {YELLOW}{BOLD}⚠ WARNING:{RESET} Some packages have medium risk indicators.")
        print(f"  These may be legitimate new packages with sparse metadata.")
    else:
        print(f"\n  {RED}{BOLD}✖ BLOCKED:{RESET} One or more packages flagged as {max_risk}.")
        print(f"  Use --force to override this security gate.")
        return False

    try:
        response = input(f"\n  Proceed with installation? [y/N]: ").strip().lower()
        return response in ("y", "yes")
    except (KeyboardInterrupt, EOFError):
        print(f"\n  {DIM}Installation cancelled.{RESET}")
        return False


def run_pip_install(packages, extra_args=None):
    """Execute the actual pip install command."""
    cmd = [sys.executable, "-m", "pip", "install"] + packages
    if extra_args:
        cmd.extend(extra_args)

    print(f"\n  {GREEN}{BOLD}Installing...{RESET} {' '.join(packages)}")
    print(f"  {DIM}Running: {' '.join(cmd)}{RESET}\n")

    try:
        result = subprocess.run(cmd, check=False)
        return result.returncode == 0
    except Exception as e:
        print(f"  {RED}Installation failed: {e}{RESET}")
        return False


def extract_packages_from_args(args):
    """
    Extract package names from command arguments.
    Handles: package, package==1.0, package>=2.0, package[extra]
    Skips pip options that start with -
    """
    packages = []
    pip_args = []

    for arg in args:
        if arg.startswith("-"):
            pip_args.append(arg)
        else:
            # Extract base package name (before ==, >=, [, etc.)
            pkg = arg.split("==")[0].split(">=")[0].split("<=")[0].split("!=")[0]
            pkg = pkg.split("[")[0].split(">")[0].split("<")[0]
            pkg = pkg.strip()
            if pkg:
                packages.append((pkg, arg))  # (clean_name, original_spec)

    return packages, pip_args


def main():
    parser = argparse.ArgumentParser(
        prog="supplyshield-install",
        description="SupplyShield Safe Install: Security-gated pip install",
        epilog="Example: supplyshield-install flask requests colorama",
    )
    parser.add_argument("packages", nargs="*", help="Package names to install")
    parser.add_argument("--force", "-f", action="store_true",
                        help="Force install even if packages are flagged")
    parser.add_argument("--scan-only", action="store_true",
                        help="Scan packages without installing")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Show detailed scan information")
    parser.add_argument("--pip-passthrough", action="store_true",
                        help="Act as pip wrapper (intercept 'install' subcommand)")

    # Parse known args, pass rest to pip
    args, remaining = parser.parse_known_args()

    # Handle pip passthrough mode
    if args.pip_passthrough:
        if not args.packages or args.packages[0] != "install":
            # Not an install command — pass through to pip directly
            cmd = [sys.executable, "-m", "pip"] + args.packages + remaining
            sys.exit(subprocess.run(cmd).returncode)
        # Remove "install" from packages list
        args.packages = args.packages[1:]

    if not args.packages and not remaining:
        parser.print_help()
        sys.exit(0)

    # Combine packages from both parsed and remaining args
    all_args = args.packages + remaining
    packages, pip_args = extract_packages_from_args(all_args)

    if not packages:
        print(f"  {RED}No packages specified.{RESET}")
        sys.exit(1)

    print_banner()

    # ── SCAN PHASE ──
    print(f"  {BOLD}Scanning {len(packages)} package(s)...{RESET}\n")

    results = []
    scan_start = time.time()

    for pkg_name, original_spec in packages:
        result = scan_package(pkg_name)
        result["original_spec"] = original_spec
        results.append(result)
        print_gate_decision(pkg_name, result)

    total_time = time.time() - scan_start
    print(f"\n  {DIM}Total scan time: {total_time:.1f}s{RESET}")

    # ── GATE DECISION ──
    decision = gate_decision(results, args.force)

    if args.scan_only:
        print(f"\n  {DIM}Scan-only mode. No installation performed.{RESET}")
        sys.exit(0)

    if decision == "proceed":
        print(f"\n  {GREEN}{BOLD}✓ All packages passed security gate.{RESET}")
        original_specs = [r["original_spec"] for r in results]
        success = run_pip_install(original_specs, pip_args)
        sys.exit(0 if success else 1)

    elif decision == "confirm":
        max_risk = max(results, key=lambda r: {"CLEAN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}.get(r["risk_level"], 0))
        if ask_confirmation([p[0] for p in packages], max_risk["risk_level"]):
            original_specs = [r["original_spec"] for r in results]
            success = run_pip_install(original_specs, pip_args)
            sys.exit(0 if success else 1)
        else:
            print(f"\n  {YELLOW}Installation cancelled by user.{RESET}")
            sys.exit(1)

    elif decision == "force":
        print(f"\n  {RED}{BOLD}⚠ FORCE OVERRIDE:{RESET} Installing flagged packages at your own risk.")
        original_specs = [r["original_spec"] for r in results]
        success = run_pip_install(original_specs, pip_args)
        sys.exit(0 if success else 1)

    else:  # block
        print(f"\n  {RED}{BOLD}✖ INSTALLATION BLOCKED{RESET}")
        print(f"  {RED}One or more packages failed the security gate.{RESET}")
        print(f"  {DIM}Use --force to override (not recommended).{RESET}")
        print(f"  {DIM}Use --scan-only to see detailed results without installing.{RESET}")
        sys.exit(1)


if __name__ == "__main__":
    main()
