#!/usr/bin/env python3
"""
SupplyShield — Live PyPI Threat Discovery Engine
==================================================
Runs the trained XGBoost classifier (F1=0.9993) against recently
published PyPI packages. Transforms SupplyShield from a research
classifier into a real-time threat discovery system.

Data Sources:
  - PyPI RSS feed (new packages): https://pypi.org/rss/packages.xml
  - PyPI RSS feed (updates):      https://pypi.org/rss/updates.xml
  - PyPI XML-RPC changelog API (most comprehensive)

Modes:
  1. SCAN:    One-time scan of N most recent packages
  2. MONITOR: Continuous monitoring with configurable interval
  3. REPORT:  Generate threat intelligence report from scan results

Usage:
  # Scan 50 most recent PyPI packages
  python src/cli/supplyshield_monitor.py scan --count 50

  # Continuous monitoring (check every 5 minutes)
  python src/cli/supplyshield_monitor.py monitor --interval 300

  # Scan and generate threat report
  python src/cli/supplyshield_monitor.py scan --count 100 --report

  # Scan only new packages published today
  python src/cli/supplyshield_monitor.py scan --since today

  # JSON output for pipeline integration
  python src/cli/supplyshield_monitor.py scan --count 20 --json

Output:
  outputs/threat_intel/scan_YYYYMMDD_HHMMSS.json
  outputs/threat_intel/threat_report_YYYYMMDD.md
  outputs/threat_intel/alerts.jsonl  (append-only alert log)


"""

import json
import os
import sys
import time
import xml.etree.ElementTree as ET
import argparse
import logging
import warnings
from datetime import datetime, timezone, timedelta
from pathlib import Path
from collections import Counter, defaultdict

warnings.filterwarnings("ignore")

# Add project root to path for imports
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src" / "cli"))

from supplyshield import (
    scan_package, load_model, load_top_packages,
    ATTACK_TAXONOMY, format_json, format_report,
)

# ============================================================================
# CONFIGURATION
# ============================================================================

PYPI_RSS_NEW = "https://pypi.org/rss/packages.xml"
PYPI_RSS_UPDATES = "https://pypi.org/rss/updates.xml"
PYPI_XMLRPC = "https://pypi.org/pypi"

OUTPUT_DIR = PROJECT_ROOT / "outputs" / "threat_intel"
ALERTS_LOG = OUTPUT_DIR / "alerts.jsonl"
SEEN_PACKAGES_FILE = OUTPUT_DIR / ".seen_packages.json"

# ANSI colors
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("monitor")


# ============================================================================
# PyPI FEED FETCHERS
# ============================================================================

def fetch_rss_packages(feed_url, max_count=100):
    """Fetch recently published packages from PyPI RSS feed."""
    import urllib.request

    logger.info(f"Fetching PyPI RSS feed: {feed_url}")
    try:
        req = urllib.request.Request(feed_url, headers={
            "User-Agent": "SupplyShield/1.0 (security research)"
        })
        with urllib.request.urlopen(req, timeout=30) as resp:
            xml_data = resp.read().decode("utf-8")
    except Exception as e:
        logger.error(f"Failed to fetch RSS feed: {e}")
        return []

    packages = []
    try:
        root = ET.fromstring(xml_data)
        channel = root.find("channel")
        if channel is None:
            return []

        for item in channel.findall("item")[:max_count]:
            title = item.findtext("title", "")
            link = item.findtext("link", "")
            pub_date = item.findtext("pubDate", "")
            description = item.findtext("description", "")

            # Extract package name from link
            # PyPI RSS link formats:
            #   https://pypi.org/project/package-name/1.0.0/  (with version)
            #   https://pypi.org/project/package-name/         (without version)
            pkg_name = ""
            version = ""

            if link:
                parts = link.rstrip("/").split("/")
                # Find "project" in the URL path — package name is always after it
                try:
                    proj_idx = parts.index("project")
                    if proj_idx + 1 < len(parts):
                        pkg_name = parts[proj_idx + 1]
                    if proj_idx + 2 < len(parts):
                        version = parts[proj_idx + 2]
                except ValueError:
                    # "project" not in URL — try last two segments
                    if len(parts) >= 2:
                        pkg_name = parts[-1]

            # Fallback: extract from title (format: "package-name X.Y.Z")
            if not pkg_name and title:
                parts = title.strip().rsplit(" ", 1)
                pkg_name = parts[0] if parts else title

            if pkg_name:
                packages.append({
                    "name": pkg_name,
                    "version": version,
                    "published": pub_date,
                    "link": link,
                    "description": description[:200],
                    "source": "rss",
                })
    except ET.ParseError as e:
        logger.error(f"Failed to parse RSS XML: {e}")

    logger.info(f"  Found {len(packages)} packages from RSS feed")
    return packages


def fetch_xmlrpc_changelog(hours=1, max_count=200):
    """
    Fetch recent package updates via PyPI XML-RPC API.
    More comprehensive than RSS — catches all uploads, not just latest 40.
    """
    import xmlrpc.client

    logger.info(f"Fetching PyPI XML-RPC changelog (last {hours}h)...")
    try:
        client = xmlrpc.client.ServerProxy(PYPI_XMLRPC, use_builtin_types=True)
        since = int((datetime.now(timezone.utc) - timedelta(hours=hours)).timestamp())
        changes = client.changelog(since)
    except Exception as e:
        logger.error(f"XML-RPC failed: {e}. Falling back to RSS.")
        return []

    # Deduplicate by package name (keep most recent)
    seen = {}
    for entry in changes:
        if len(entry) >= 4:
            name, version, timestamp, action = entry[:4]
            if action in ("new release", "create"):
                if name not in seen or timestamp > seen[name]["timestamp"]:
                    seen[name] = {
                        "name": name,
                        "version": version,
                        "timestamp": timestamp,
                        "action": action,
                        "source": "xmlrpc",
                    }

    packages = sorted(seen.values(), key=lambda x: x.get("timestamp", 0), reverse=True)
    packages = packages[:max_count]

    logger.info(f"  Found {len(packages)} unique packages from XML-RPC changelog")
    return packages


def fetch_recent_packages(method="rss", count=50, hours=1):
    """Fetch recent packages using specified method."""
    if method == "xmlrpc":
        packages = fetch_xmlrpc_changelog(hours=hours, max_count=count)
        if not packages:
            logger.info("XML-RPC returned empty, falling back to RSS")
            packages = fetch_rss_packages(PYPI_RSS_NEW, max_count=count)
    elif method == "both":
        rss_new = fetch_rss_packages(PYPI_RSS_NEW, max_count=count)
        rss_updates = fetch_rss_packages(PYPI_RSS_UPDATES, max_count=count)

        # Merge and deduplicate
        seen = {}
        for pkg in rss_new + rss_updates:
            name = pkg["name"]
            if name not in seen:
                seen[name] = pkg
        packages = list(seen.values())[:count]
    else:
        packages = fetch_rss_packages(PYPI_RSS_NEW, max_count=count)

    return packages


# ============================================================================
# SEEN PACKAGES TRACKING (avoid re-scanning)
# ============================================================================

def load_seen_packages():
    """Load set of previously scanned packages."""
    if SEEN_PACKAGES_FILE.exists():
        try:
            with open(SEEN_PACKAGES_FILE) as f:
                data = json.load(f)
            return set(data.get("packages", []))
        except Exception:
            pass
    return set()


def save_seen_packages(seen):
    """Save seen packages set."""
    SEEN_PACKAGES_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(SEEN_PACKAGES_FILE, "w") as f:
        json.dump({
            "packages": list(seen),
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "count": len(seen),
        }, f)


# ============================================================================
# ALERT LOGGING
# ============================================================================

def log_alert(result, pkg_info):
    """Append alert to JSONL log file."""
    ALERTS_LOG.parent.mkdir(parents=True, exist_ok=True)
    alert = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "package": pkg_info["name"],
        "version": pkg_info.get("version", ""),
        "risk_level": result["risk_level"],
        "confidence": result["confidence"],
        "attack_vector": result.get("attack_vector", "AV-000"),
        "attack_name": ATTACK_TAXONOMY.get(result.get("attack_vector", "AV-000"), {}).get("name"),
        "modalities": result["modalities"],
        "scan_time": result["scan_time"],
        "published": pkg_info.get("published", ""),
        "link": pkg_info.get("link", ""),
    }
    with open(ALERTS_LOG, "a") as f:
        f.write(json.dumps(alert) + "\n")


# ============================================================================
# SCAN ENGINE
# ============================================================================

def scan_recent_packages(packages, skip_seen=True):
    """Scan a list of packages and return results."""
    seen = load_seen_packages() if skip_seen else set()
    results = []
    alerts = []
    skipped = 0

    total = len(packages)
    logger.info(f"\nScanning {total} packages...")
    logger.info(f"{'='*60}")

    for i, pkg_info in enumerate(packages, 1):
        pkg_name = pkg_info["name"]

        # Skip already scanned
        pkg_key = f"{pkg_name}:{pkg_info.get('version', 'latest')}"
        if skip_seen and pkg_key in seen:
            skipped += 1
            continue

        # Scan
        try:
            result = scan_package(pkg_name, pkg_info.get("version") or None)
        except Exception as e:
            logger.debug(f"Error scanning {pkg_name}: {e}")
            result = {
                "prediction": 0, "confidence": 0.0, "risk_level": "ERROR",
                "modalities": {"metadata": False, "code": False, "stylometric": False},
                "attack_vector": "AV-000", "secondary_vectors": [],
                "top_features": [], "scan_time": 0.0,
            }

        result["package_info"] = pkg_info
        results.append(result)
        seen.add(pkg_key)

        # Color-coded output
        risk = result["risk_level"]
        if risk in ("CRITICAL", "HIGH"):
            color = RED
            marker = "\u2620 "  # skull
            alerts.append(result)
            log_alert(result, pkg_info)
        elif risk == "MEDIUM":
            color = YELLOW
            marker = "\u26A0 "  # warning
            alerts.append(result)
            log_alert(result, pkg_info)
        elif risk == "ERROR":
            color = DIM
            marker = "? "
        else:
            color = GREEN
            marker = "\u2713 "  # check

        # Progress line
        av = result.get("attack_vector", "AV-000")
        av_name = ATTACK_TAXONOMY.get(av, {}).get("name", "")
        mods = ""
        if result["modalities"]["code"]:
            mods += " [Code]"
        if result["modalities"]["stylometric"]:
            mods += " [Sty]"

        if risk in ("CRITICAL", "HIGH", "MEDIUM"):
            logger.info(f"  [{i}/{total}] {color}{BOLD}{marker}{pkg_name}{RESET} "
                        f"→ {color}{risk}{RESET} | {av} ({av_name}){mods} "
                        f"| {result['scan_time']:.1f}s")
        else:
            logger.info(f"  [{i}/{total}] {color}{marker}{pkg_name}{RESET} "
                        f"→ {risk}{mods} | {result['scan_time']:.1f}s")

    # Save seen packages
    save_seen_packages(seen)

    return results, alerts, skipped


# ============================================================================
# THREAT INTELLIGENCE REPORT
# ============================================================================

def generate_threat_report(results, alerts, scan_metadata):
    """Generate a Markdown threat intelligence report."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = []
    w = lines.append

    w("# SupplyShield Threat Intelligence Report")
    w("")
    w(f"**Generated:** {now}")
    w("")
    w(f"**Scan Type:** {scan_metadata.get('scan_type', 'manual')}")
    w(f"**Packages Scanned:** {len(results)}")
    w(f"**Alerts Generated:** {len(alerts)}")
    w(f"**Total Scan Time:** {sum(r['scan_time'] for r in results):.1f}s")
    w("")
    w("---")
    w("")

    # ── Summary Statistics ──
    w("## 1. Scan Summary")
    w("")

    risk_counts = Counter(r["risk_level"] for r in results)
    w("| Risk Level | Count | Percentage |")
    w("|-----------|-------|-----------|")
    for risk in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "CLEAN", "ERROR"]:
        count = risk_counts.get(risk, 0)
        if count > 0:
            pct = count / max(len(results), 1) * 100
            w(f"| {risk} | {count} | {pct:.1f}% |")
    w("")

    av_counts = Counter()
    for r in results:
        if r["prediction"] == 1:
            av_counts[r.get("attack_vector", "AV-000")] += 1

    if av_counts:
        w("### Attack Vector Distribution")
        w("")
        w("| Attack Vector | Count |")
        w("|--------------|-------|")
        for av, count in sorted(av_counts.items(), key=lambda x: -x[1]):
            name = ATTACK_TAXONOMY.get(av, {}).get("name", "Unknown")
            w(f"| {av} ({name}) | {count} |")
        w("")

    # Modality coverage
    meta_count = sum(1 for r in results if r["modalities"]["metadata"])
    code_count = sum(1 for r in results if r["modalities"]["code"])
    sty_count = sum(1 for r in results if r["modalities"]["stylometric"])
    w("### Modality Coverage")
    w("")
    w(f"- Metadata analyzed: {meta_count}/{len(results)} ({meta_count/max(len(results),1)*100:.0f}%)")
    w(f"- Code analyzed: {code_count}/{len(results)} ({code_count/max(len(results),1)*100:.0f}%)")
    w(f"- Stylometric analyzed: {sty_count}/{len(results)} ({sty_count/max(len(results),1)*100:.0f}%)")
    w("")

    # ── Alerts Detail ──
    if alerts:
        w("## 2. Threat Alerts")
        w("")
        for i, alert in enumerate(alerts, 1):
            pkg = alert.get("package_info", {}).get("name", "unknown")
            risk = alert["risk_level"]
            av = alert.get("attack_vector", "AV-000")
            av_info = ATTACK_TAXONOMY.get(av, {})
            conf = alert["confidence"]

            w(f"### Alert {i}: `{pkg}` — {risk}")
            w("")
            w(f"- **Risk Level:** {risk} (confidence: {conf:.1%})")
            w(f"- **Attack Vector:** {av} \u2014 {av_info.get('name', 'Unknown')}")
            w(f"- **Severity:** {av_info.get('severity', 'N/A')}")
            w(f"- **MITRE ATT&CK:** {av_info.get('mitre', 'N/A')}")
            w(f"- **Scan Time:** {alert['scan_time']:.1f}s")

            pkg_info = alert.get("package_info", {})
            if pkg_info.get("published"):
                w(f"- **Published:** {pkg_info['published']}")
            if pkg_info.get("link"):
                w(f"- **Link:** {pkg_info['link']}")
            w("")

            if alert.get("top_features"):
                w("**Top Indicators:**")
                w("")
                w("| Feature | SHAP Value | Direction |")
                w("|---------|-----------|-----------|")
                for feat in alert["top_features"][:5]:
                    direction = "Suspicious" if feat["shap_value"] > 0 else "Absent/low"
                    w(f"| {feat.get('description', feat['feature'])} | "
                      f"{feat['shap_value']:+.3f} | {direction} |")
                w("")

            if alert.get("secondary_vectors"):
                sec = ", ".join([f"{v} ({ATTACK_TAXONOMY[v]['name']})"
                                 for v in alert["secondary_vectors"][:3]])
                w(f"**Secondary Indicators:** {sec}")
                w("")

            w("---")
            w("")
    else:
        w("## 2. Threat Alerts")
        w("")
        w("No threats detected in this scan.")
        w("")

    # ── Scan Performance ──
    w("## 3. Scan Performance")
    w("")
    scan_times = [r["scan_time"] for r in results]
    if scan_times:
        w(f"- **Average scan time:** {sum(scan_times)/len(scan_times):.2f}s per package")
        w(f"- **Fastest scan:** {min(scan_times):.2f}s")
        w(f"- **Slowest scan:** {max(scan_times):.2f}s")
        w(f"- **Total time:** {sum(scan_times):.1f}s for {len(results)} packages")
        w(f"- **Throughput:** {len(results)/max(sum(scan_times), 0.1):.1f} packages/second")
    w("")

    w("---")
    w(f"*Generated by SupplyShield Monitor v1.0 on {now}*")

    return "\n".join(lines)


# ============================================================================
# MAIN COMMANDS
# ============================================================================

def cmd_scan(args):
    """One-time scan of recent packages."""
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    # Determine time range
    hours = 24
    if args.since == "today":
        hours = (datetime.now(timezone.utc) - datetime.now(timezone.utc).replace(
            hour=0, minute=0, second=0, microsecond=0)).total_seconds() / 3600
        hours = max(hours, 1)
    elif args.since:
        try:
            hours = int(args.since)
        except ValueError:
            hours = 24

    # Fetch packages
    packages = fetch_recent_packages(
        method=args.method,
        count=args.count,
        hours=hours,
    )

    if not packages:
        logger.warning("No packages found to scan.")
        return

    # Scan
    results, alerts, skipped = scan_recent_packages(
        packages, skip_seen=not args.rescan
    )

    # Summary
    logger.info("")
    logger.info(f"{'='*60}")
    logger.info(f"SCAN COMPLETE")
    logger.info(f"{'='*60}")
    logger.info(f"  Packages scanned: {len(results)}")
    logger.info(f"  Skipped (seen):   {skipped}")
    logger.info(f"  Alerts:           {len(alerts)}")

    risk_counts = Counter(r["risk_level"] for r in results)
    for risk in ["CRITICAL", "HIGH", "MEDIUM"]:
        if risk_counts.get(risk, 0) > 0:
            color = RED if risk in ("CRITICAL", "HIGH") else YELLOW
            logger.info(f"  {color}{risk}: {risk_counts[risk]}{RESET}")

    logger.info(f"  Clean:            {risk_counts.get('CLEAN', 0)}")

    # Save results
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    results_path = OUTPUT_DIR / f"scan_{timestamp}.json"

    # Serialize results
    serializable = []
    for r in results:
        entry = {
            "package": r.get("package_info", {}).get("name", "unknown"),
            "version": r.get("package_info", {}).get("version", ""),
            "risk_level": r["risk_level"],
            "confidence": r["confidence"],
            "prediction": "malicious" if r["prediction"] == 1 else "benign",
            "attack_vector": r.get("attack_vector", "AV-000"),
            "modalities": r["modalities"],
            "scan_time": round(r["scan_time"], 3),
        }
        if r.get("top_features"):
            entry["top_features"] = r["top_features"][:5]
        if r.get("secondary_vectors"):
            entry["secondary_vectors"] = r["secondary_vectors"]
        serializable.append(entry)

    scan_data = {
        "scan_metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "method": args.method,
            "packages_requested": args.count,
            "packages_scanned": len(results),
            "packages_skipped": skipped,
            "alerts_generated": len(alerts),
            "total_scan_time": round(sum(r["scan_time"] for r in results), 2),
        },
        "results": serializable,
    }

    with open(results_path, "w") as f:
        json.dump(scan_data, f, indent=2, default=str)
    logger.info(f"  Results saved: {results_path}")

    # Generate report if requested
    if args.report:
        report_path = OUTPUT_DIR / f"threat_report_{timestamp}.md"
        report = generate_threat_report(results, alerts, scan_data["scan_metadata"])
        with open(report_path, "w") as f:
            f.write(report)
        logger.info(f"  Report saved: {report_path}")

    # JSON output mode
    if args.json:
        print(json.dumps(scan_data, indent=2, default=str))

    logger.info(f"{'='*60}")

    return results, alerts


def cmd_monitor(args):
    """Continuous monitoring mode."""
    logger.info(f"{'='*60}")
    logger.info(f"SupplyShield — Continuous Monitoring Mode")
    logger.info(f"  Interval: {args.interval}s | Method: {args.method}")
    logger.info(f"  Press Ctrl+C to stop")
    logger.info(f"{'='*60}")

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    scan_count = 0
    total_alerts = 0

    try:
        while True:
            scan_count += 1
            logger.info(f"\n{'─'*40}")
            logger.info(f"Scan #{scan_count} at {datetime.now(timezone.utc).strftime('%H:%M:%S UTC')}")
            logger.info(f"{'─'*40}")

            packages = fetch_recent_packages(
                method=args.method,
                count=args.count,
                hours=max(args.interval / 3600 * 2, 1),  # Look back 2x the interval
            )

            if packages:
                results, alerts, skipped = scan_recent_packages(
                    packages, skip_seen=True
                )
                total_alerts += len(alerts)

                if alerts:
                    logger.info(f"\n{RED}{BOLD}\u26A0 {len(alerts)} NEW ALERT(S) DETECTED{RESET}")
                    for alert in alerts:
                        pkg = alert.get("package_info", {}).get("name", "unknown")
                        av = alert.get("attack_vector", "AV-000")
                        logger.info(f"  {RED}\u2620 {pkg} → {alert['risk_level']} "
                                    f"({ATTACK_TAXONOMY.get(av, {}).get('name', 'Unknown')}){RESET}")
                else:
                    new_count = len(results)
                    if new_count > 0:
                        logger.info(f"  {GREEN}\u2713 {new_count} new packages scanned — all clean{RESET}")
                    else:
                        logger.info(f"  {DIM}No new packages since last scan{RESET}")
            else:
                logger.info(f"  {DIM}No packages from feed{RESET}")

            logger.info(f"  Total alerts this session: {total_alerts}")
            logger.info(f"  Next scan in {args.interval}s...")
            time.sleep(args.interval)

    except KeyboardInterrupt:
        logger.info(f"\n\n{'='*60}")
        logger.info(f"Monitoring stopped.")
        logger.info(f"  Total scans: {scan_count}")
        logger.info(f"  Total alerts: {total_alerts}")
        logger.info(f"  Alert log: {ALERTS_LOG}")
        logger.info(f"{'='*60}")


def cmd_history(args):
    """Show alert history from the JSONL log."""
    if not ALERTS_LOG.exists():
        print("No alert history found.")
        return

    alerts = []
    with open(ALERTS_LOG) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    alerts.append(json.loads(line))
                except json.JSONDecodeError:
                    pass

    if not alerts:
        print("No alerts recorded.")
        return

    # Filter by risk level if specified
    if args.risk:
        alerts = [a for a in alerts if a["risk_level"] == args.risk.upper()]

    # Show most recent first
    alerts.reverse()
    alerts = alerts[:args.count]

    print(f"\n{BOLD}SupplyShield Alert History ({len(alerts)} alerts){RESET}\n")
    print(f"{'Timestamp':<22} {'Package':<30} {'Risk':<10} {'Attack Vector':<25}")
    print("-" * 90)

    for alert in alerts:
        ts = alert.get("timestamp", "")[:19]
        pkg = alert.get("package", "?")[:28]
        risk = alert.get("risk_level", "?")
        av = alert.get("attack_vector", "?")
        av_name = alert.get("attack_name", "")

        color = RED if risk in ("CRITICAL", "HIGH") else YELLOW if risk == "MEDIUM" else RESET
        print(f"{ts:<22} {pkg:<30} {color}{risk:<10}{RESET} {av} ({av_name})")

    print(f"\nFull log: {ALERTS_LOG}")


# ============================================================================
# CLI ENTRY POINT
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        prog="supplyshield-monitor",
        description="SupplyShield: Live PyPI Threat Discovery Engine",
    )
    subparsers = parser.add_subparsers(dest="command")

    # scan command
    scan_parser = subparsers.add_parser("scan", help="One-time scan of recent packages")
    scan_parser.add_argument("--count", "-n", type=int, default=40,
                              help="Number of packages to scan (default: 40)")
    scan_parser.add_argument("--method", choices=["rss", "xmlrpc", "both"], default="rss",
                              help="Package discovery method (default: rss)")
    scan_parser.add_argument("--since", default=None,
                              help="Time range: 'today', or hours (e.g., '6')")
    scan_parser.add_argument("--report", action="store_true",
                              help="Generate threat intelligence report")
    scan_parser.add_argument("--json", action="store_true",
                              help="Output results as JSON")
    scan_parser.add_argument("--rescan", action="store_true",
                              help="Re-scan previously seen packages")

    # monitor command
    monitor_parser = subparsers.add_parser("monitor", help="Continuous monitoring")
    monitor_parser.add_argument("--interval", "-i", type=int, default=300,
                                 help="Seconds between scans (default: 300)")
    monitor_parser.add_argument("--count", "-n", type=int, default=40,
                                 help="Packages per scan cycle (default: 40)")
    monitor_parser.add_argument("--method", choices=["rss", "xmlrpc", "both"], default="rss",
                                 help="Discovery method (default: rss)")

    # history command
    history_parser = subparsers.add_parser("history", help="View alert history")
    history_parser.add_argument("--count", "-n", type=int, default=50,
                                 help="Number of alerts to show (default: 50)")
    history_parser.add_argument("--risk", choices=["critical", "high", "medium"],
                                 help="Filter by risk level")

    args = parser.parse_args()

    if args.command == "scan":
        cmd_scan(args)
    elif args.command == "monitor":
        cmd_monitor(args)
    elif args.command == "history":
        cmd_history(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
