import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
import json
import os
from pathlib import Path

# ─────────────────────────────
# SETTINGS — AUTO DETECT FILES
# ─────────────────────────────

# Base directory = wherever analysis.py is located
BASE_DIR     = Path(__file__).parent
RESULTS_DIR  = BASE_DIR / "results"
CHARTS_DIR   = BASE_DIR / "charts"
CHARTS_DIR.mkdir(parents=True, exist_ok=True)

# Auto find latest Prowler CSV file
prowler_files = list((RESULTS_DIR / "prowler").glob("*.csv"))
if not prowler_files:
    print("ERROR: No Prowler CSV found in analysis/results/prowler/")
    print("       Run Prowler scan first.")
    exit(1)
PROWLER_FILE = max(prowler_files, key=os.path.getmtime)
print(f"[+] Prowler file found: {PROWLER_FILE.name}")

# Auto find latest ScoutSuite JS results file
scoutsuite_files = list((RESULTS_DIR / "scoutsuite").rglob("scoutsuite_results_*.js"))
if not scoutsuite_files:
    print("ERROR: No ScoutSuite results found in analysis/results/scoutsuite/")
    print("       Run ScoutSuite scan first.")
    exit(1)
SCOUTSUITE_FILE = max(scoutsuite_files, key=os.path.getmtime)
print(f"[+] ScoutSuite file found: {SCOUTSUITE_FILE.name}")

# ─────────────────────────────
# LOAD PROWLER DATA
# ─────────────────────────────
print("=" * 50)
print("LOADING PROWLER RESULTS")
print("=" * 50)

df = pd.read_csv(
    PROWLER_FILE,
    sep=";",
    engine="python",
    encoding="utf-8",
    on_bad_lines="skip"
)

failed = df[df["STATUS"] == "FAIL"]
passed = df[df["STATUS"] == "PASS"]

print(f"Total checks : {len(df)}")
print(f"Failed       : {len(failed)}")
print(f"Passed       : {len(passed)}")
print(f"\nSeverity breakdown:")
print(failed["SEVERITY"].value_counts())
print(f"\nService breakdown:")
print(failed["SERVICE_NAME"].value_counts())

# ─────────────────────────────
# LOAD SCOUTSUITE DATA
# ─────────────────────────────
print("\n")
print("=" * 50)
print("LOADING SCOUTSUITE RESULTS")
print("=" * 50)

with open(SCOUTSUITE_FILE, "r", encoding="utf-8") as f:
    content = f.read()

# Strip the javascript variable assignment
content = content.replace("scoutsuite_results =", "").strip()
data = json.loads(content)

# Extract service findings
services_data = data.get("services", {})

scoutsuite_summary = {}
for service_name, service_data in services_data.items():
    if service_name not in ["ec2", "iam", "s3"]:
        continue

    findings = service_data.get("findings", {})
    danger = 0
    warning = 0
    info = 0

    for finding_key, finding in findings.items():
        level = finding.get("level", "")
        flagged = finding.get("flagged_items", 0)
        if flagged > 0:
            if level == "danger":
                danger += 1
            elif level == "warning":
                warning += 1
            else:
                info += 1

    scoutsuite_summary[service_name] = {
        "danger": danger,
        "warning": warning,
        "info": info
    }

print(f"\nScoutSuite findings per service:")
for svc, vals in scoutsuite_summary.items():
    total = vals["danger"] + vals["warning"] + vals["info"]
    print(f"  {svc.upper():<6} Danger={vals['danger']}  Warning={vals['warning']}  Info={vals['info']}  Total={total}")

# ─────────────────────────────
# CHART 1: PROWLER SEVERITY DISTRIBUTION
# ─────────────────────────────
print("\nGenerating charts...")

severity_order = ["critical", "high", "medium", "low"]
severity_colors = ["#D32F2F", "#F57C00", "#FBC02D", "#388E3C"]
severity_counts = failed["SEVERITY"].value_counts()
values = [severity_counts.get(s, 0) for s in severity_order]

fig, ax = plt.subplots(figsize=(8, 5))
bars = ax.bar(
    [s.upper() for s in severity_order],
    values,
    color=severity_colors,
    alpha=0.85,
    width=0.5
)
for bar, val in zip(bars, values):
    ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.3,
            str(val), ha="center", va="bottom", fontsize=12, fontweight="bold")

ax.set_title("Prowler — Severity Distribution of Failed Checks", fontsize=13, fontweight="bold")
ax.set_xlabel("Severity Level", fontsize=11)
ax.set_ylabel("Number of Findings", fontsize=11)
ax.set_ylim(0, max(values) + 5)
ax.grid(axis="y", linestyle="--", alpha=0.4)
plt.tight_layout()
plt.savefig(os.path.join(CHARTS_DIR, "chart1_prowler_severity.png"), dpi=150)
plt.close()
print("  Saved: chart1_prowler_severity.png")

# ─────────────────────────────
# CHART 2: PROWLER SERVICE BREAKDOWN
# ─────────────────────────────
service_counts = failed["SERVICE_NAME"].value_counts()
services = service_counts.index.tolist()
svc_values = service_counts.values.tolist()
svc_colors = ["#2196F3", "#FF5722", "#4CAF50"]

fig, ax = plt.subplots(figsize=(8, 5))
bars = ax.bar(
    [s.upper() for s in services],
    svc_values,
    color=svc_colors,
    alpha=0.85,
    width=0.5
)
for bar, val in zip(bars, svc_values):
    ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.3,
            str(val), ha="center", va="bottom", fontsize=12, fontweight="bold")

ax.set_title("Prowler — Failed Checks by AWS Service", fontsize=13, fontweight="bold")
ax.set_xlabel("AWS Service", fontsize=11)
ax.set_ylabel("Number of Failed Checks", fontsize=11)
ax.set_ylim(0, max(svc_values) + 5)
ax.grid(axis="y", linestyle="--", alpha=0.4)
plt.tight_layout()
plt.savefig(os.path.join(CHARTS_DIR, "chart2_prowler_services.png"), dpi=150)
plt.close()
print("  Saved: chart2_prowler_services.png")

# ─────────────────────────────
# CHART 3: TOTAL FINDINGS COMPARISON
# ─────────────────────────────
prowler_total = len(failed)
scoutsuite_total = sum(
    v["danger"] + v["warning"]
    for v in scoutsuite_summary.values()
)

tools = ["Prowler", "ScoutSuite"]
totals = [prowler_total, scoutsuite_total]
colors = ["#2196F3", "#FF5722"]

fig, ax = plt.subplots(figsize=(8, 5))
bars = ax.bar(tools, totals, color=colors, alpha=0.85, width=0.4)
for bar, val in zip(bars, totals):
    ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.3,
            str(val), ha="center", va="bottom", fontsize=13, fontweight="bold")

ax.set_title("Total Findings: Prowler vs ScoutSuite", fontsize=13, fontweight="bold")
ax.set_ylabel("Number of Findings", fontsize=11)
ax.set_ylim(0, max(totals) + 10)
ax.grid(axis="y", linestyle="--", alpha=0.4)
plt.tight_layout()
plt.savefig(os.path.join(CHARTS_DIR, "chart3_total_comparison.png"), dpi=150)
plt.close()
print("  Saved: chart3_total_comparison.png")

# ─────────────────────────────
# CHART 4: SERVICE COMPARISON SIDE BY SIDE
# ─────────────────────────────
service_labels = ["EC2", "IAM", "S3"]
prowler_vals = [
    len(failed[failed["SERVICE_NAME"] == "ec2"]),
    len(failed[failed["SERVICE_NAME"] == "iam"]),
    len(failed[failed["SERVICE_NAME"] == "s3"]),
]
scoutsuite_vals = [
    scoutsuite_summary.get("ec2", {}).get("danger", 0) + scoutsuite_summary.get("ec2", {}).get("warning", 0),
    scoutsuite_summary.get("iam", {}).get("danger", 0) + scoutsuite_summary.get("iam", {}).get("warning", 0),
    scoutsuite_summary.get("s3", {}).get("danger", 0) + scoutsuite_summary.get("s3", {}).get("warning", 0),
]

x = np.arange(len(service_labels))
width = 0.35

fig, ax = plt.subplots(figsize=(9, 5))
bars1 = ax.bar(x - width / 2, prowler_vals, width, label="Prowler", color="#2196F3", alpha=0.85)
bars2 = ax.bar(x + width / 2, scoutsuite_vals, width, label="ScoutSuite", color="#FF5722", alpha=0.85)

for bar in bars1:
    ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.2,
            str(int(bar.get_height())), ha="center", va="bottom", fontsize=11, fontweight="bold")
for bar in bars2:
    ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.2,
            str(int(bar.get_height())), ha="center", va="bottom", fontsize=11, fontweight="bold")

ax.set_title("Findings per Service: Prowler vs ScoutSuite", fontsize=13, fontweight="bold")
ax.set_xlabel("AWS Service", fontsize=11)
ax.set_ylabel("Number of Findings", fontsize=11)
ax.set_xticks(x)
ax.set_xticklabels(service_labels)
ax.legend(fontsize=11)
ax.grid(axis="y", linestyle="--", alpha=0.4)
plt.tight_layout()
plt.savefig(os.path.join(CHARTS_DIR, "chart4_service_comparison.png"), dpi=150)
plt.close()
print("  Saved: chart4_service_comparison.png")

# ─────────────────────────────
# CHART 5: SCOUTSUITE DANGER vs WARNING
# ─────────────────────────────
svc_labels = ["EC2", "IAM", "S3"]
dangers = [scoutsuite_summary.get(s.lower(), {}).get("danger", 0) for s in svc_labels]
warnings = [scoutsuite_summary.get(s.lower(), {}).get("warning", 0) for s in svc_labels]

x = np.arange(len(svc_labels))
width = 0.35

fig, ax = plt.subplots(figsize=(9, 5))
bars1 = ax.bar(x - width / 2, dangers, width, label="Danger", color="#D32F2F", alpha=0.85)
bars2 = ax.bar(x + width / 2, warnings, width, label="Warning", color="#FBC02D", alpha=0.85)

for bar in bars1:
    ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.1,
            str(int(bar.get_height())), ha="center", va="bottom", fontsize=11, fontweight="bold")
for bar in bars2:
    ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.1,
            str(int(bar.get_height())), ha="center", va="bottom", fontsize=11, fontweight="bold")

ax.set_title("ScoutSuite — Danger vs Warning per Service", fontsize=13, fontweight="bold")
ax.set_xlabel("AWS Service", fontsize=11)
ax.set_ylabel("Number of Findings", fontsize=11)
ax.set_xticks(x)
ax.set_xticklabels(svc_labels)
ax.legend(fontsize=11)
ax.grid(axis="y", linestyle="--", alpha=0.4)
plt.tight_layout()
plt.savefig(os.path.join(CHARTS_DIR, "chart5_scoutsuite_breakdown.png"), dpi=150)
plt.close()
print("  Saved: chart5_scoutsuite_breakdown.png")

# ─────────────────────────────
# CHART 6: RADAR CHART
# ─────────────────────────────
categories = [
    "Detection\nBreadth",
    "Compliance\nCoverage",
    "Ease of\nUse",
    "Report\nQuality",
    "Speed",
    "Attack\nSurface"
]
N = len(categories)

prowler_scores = [9, 9, 7, 6, 7, 4]
scoutsuite_scores = [7, 5, 8, 9, 8, 8]

angles = [n / float(N) * 2 * np.pi for n in range(N)]
angles += angles[:1]
prowler_scores += prowler_scores[:1]
scoutsuite_scores += scoutsuite_scores[:1]

fig, ax = plt.subplots(figsize=(7, 7), subplot_kw={"projection": "polar"})
ax.plot(angles, prowler_scores, color="#2196F3", linewidth=2, label="Prowler")
ax.fill(angles, prowler_scores, color="#2196F3", alpha=0.25)
ax.plot(angles, scoutsuite_scores, color="#FF5722", linewidth=2, label="ScoutSuite")
ax.fill(angles, scoutsuite_scores, color="#FF5722", alpha=0.25)
ax.set_xticks(angles[:-1])
ax.set_xticklabels(categories, fontsize=10)
ax.set_ylim(0, 10)
ax.set_title("Tool Capability Comparison\n(Score out of 10)",
             fontsize=13, fontweight="bold", pad=20)
ax.legend(loc="upper right", bbox_to_anchor=(1.3, 1.1), fontsize=11)
plt.tight_layout()
plt.savefig(os.path.join(CHARTS_DIR, "chart6_radar.png"), dpi=150)
plt.close()
print("  Saved: chart6_radar.png")

# ─────────────────────────────
# FINAL SUMMARY
# ─────────────────────────────
print("\n")
print("=" * 50)
print("FINAL COMPARISON SUMMARY")
print("=" * 50)
print(f"\n{'Metric':<30} {'Prowler':>12} {'ScoutSuite':>12}")
print("-" * 55)
print(f"{'Total Findings':<30} {prowler_total:>12} {scoutsuite_total:>12}")
print(f"{'EC2 Findings':<30} {prowler_vals[0]:>12} {scoutsuite_vals[0]:>12}")
print(f"{'IAM Findings':<30} {prowler_vals[1]:>12} {scoutsuite_vals[1]:>12}")
print(f"{'S3 Findings':<30} {prowler_vals[2]:>12} {scoutsuite_vals[2]:>12}")
print(f"{'Approach':<30} {'Rule-based':>12} {'Attack surface':>12}")
print(f"{'Output Format':<30} {'CSV/JSON':>12} {'HTML':>12}")
print(f"\nAll charts saved to: {CHARTS_DIR}")
print("\n✅ Analysis complete!")