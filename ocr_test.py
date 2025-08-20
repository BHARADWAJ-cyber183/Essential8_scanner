import pytesseract
from PIL import Image
import os
import csv

# Define rule keywords for each strategy
strategy_rules = {
    "Patch Applications": [
        "update", "outdated", "install patch",
        "missing patch", "critical update", "vulnerability"
    ],
    "User Application Hardening": [
        "internet explorer", "legacy", "activex", 
        "ie11", "unsupported", "old browser", 
        "discontinued", "retired browser", "microsoft edge"
    ],
    "Restrict Admin Privileges": [
        "admin rights", "administrator", "elevated",
        "user privileges", "local admin"
    ],
    "Office Macros": [
        "macro settings", "enable macros", "disable macros",
        "macro virus", "vba"
    ],
    "Patch OS": [
        "windows update", "system update", "os version",
        "security patch", "service pack"
    ],
    "Application Control": [
        "app locker", "application whitelist", "software restriction",
        "block programs", "restricted apps"
    ],
    "MFA": [
        "multi-factor", "two-factor", "2fa", "mfa",
        "otp", "authenticator app", "sms verification"
    ],
    "Backup Strategy": [
        "backup", "restore point", "recovery",
        "snapshot", "cloud backup", "system restore"
    ]
}

# List strategies
strategies = list(strategy_rules.keys())

print("Available strategies:")
for i, strategy in enumerate(strategies, 1):
    print(f"{i}. {strategy}")

# Ask user to select strategies
selected_numbers = input("Select strategies by number (e.g. 1,3,5): ").split(",")
selected_strategies = [strategies[int(num.strip()) - 1] for num in selected_numbers if num.strip().isdigit() and 1 <= int(num.strip()) <= len(strategies)]

print("\n📋 Scanning using strategies:", ", ".join(selected_strategies), "\n")

# Prepare report data
report_rows = [("Image", "Strategy", "Findings")]

# OCR each PNG image in the "screenshots" folder
for file in os.listdir("screenshots"):
    if file.lower().endswith(".png"):
        print(f"🖼️  {file}:")
        img_path = os.path.join("screenshots", file)
        img = Image.open(img_path)
        text = pytesseract.image_to_string(img).lower()

        print("📝 OCR Text:", text)  # Optional debug print

        for strategy in selected_strategies:
            findings = [word for word in strategy_rules[strategy] if word in text]
            if findings:
                print(f"🔍 Findings Detected ({strategy}):", ", ".join(findings))
                report_rows.append((file, strategy, ", ".join(findings)))

# Save CSV
with open("scan_report.csv", "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerows(report_rows)

print("\n Report saved as: scan_report.csv")
