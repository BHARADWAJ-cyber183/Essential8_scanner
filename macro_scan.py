# macro_scan.py
# Purpose: Essential Eight (Level 1) - Configure Microsoft Office Macro Settings validator
# Inputs: files under ./screenshots (PNG/JPG screenshots and .txt/.reg exports)
# Output: macro_report.csv (TestID, File/Evidence, Status, Findings)

import os
import re
import csv
import pytesseract
from PIL import Image

SCREENSHOTS_DIR = "screenshots"
OUT_CSV = "macro_report.csv"

# -----------------------------
# Helpers
# -----------------------------
def is_image(path: str) -> bool:
    low = path.lower()
    return low.endswith((".png", ".jpg", ".jpeg", ".bmp", ".tif", ".tiff"))

def extract_text(path: str) -> str:
    """OCR for images; raw read for .txt/.reg; lowercased normalized text."""
    try:
        if is_image(path):
            img = Image.open(path)
            text = pytesseract.image_to_string(img)
        else:
            with open(path, "r", errors="ignore") as f:
                text = f.read()
    except Exception:
        text = ""
    # normalize
    text = re.sub(r"\s+", " ", text).strip().lower()
    return text

def grep_any(text: str, needles):
    return any(n in text for n in needles)

def find_registry_value(text: str, key_regex: str, value_name: str):
    """
    Parse .reg export / PowerShell output and return integer if found.
    Accepts hex (0x...) or decimal.
    """
    if not re.search(key_regex, text, flags=re.IGNORECASE):
        return None
    m = re.search(rf"{re.escape(value_name)}[^0-9a-fx]*([0-9]+|0x[0-9a-f]+)", text, flags=re.IGNORECASE)
    if not m:
        return None
    raw = m.group(1)
    try:
        return int(raw, 0)
    except Exception:
        return None

# -----------------------------
# Test logic per control
# -----------------------------

def test_ml1_om_01(text: str):
    """
    Blocking macros for unapproved users: look for RSOP/Trust Center strings or VBAWarnings=3.
    Pass if 'disable without notification' present or VBAWarnings == 3 under policy path.
    """
    ok = False
    notes = []
    if "disable without notification" in text and "macro" in text:
        ok = True
        notes.append("RSOP/Trust Center shows 'Disable without notification'.")
    else:
        # HKCU\Software\Policies\Microsoft\Office\<ver>\<app>\Security -> VBAWarnings=3
        for app in ("word", "excel", "powerpoint"):
            val = find_registry_value(
                text,
                rf"software\\policies\\microsoft\\office\\(14\.0|15\.0|16\.0)\\{app}\\security",
                "vbawarnings"
            )
            if val is not None:
                notes.append(f"{app}: VBAWarnings={val}")
                if val == 3:
                    ok = True
    return ok, "; ".join(notes) if notes else "No matching evidence."

def test_ml1_om_02(approved_text: str, adgroup_text: str):
    """
    Approved users list vs AD group membership.
    Pass if sets match. If either input is missing/empty, mark Insufficient.
    """
    if not approved_text.strip() or not adgroup_text.strip():
        return "Insufficient Evidence", "Need both Approved Users list and AD group membership export."

    # extract simple identifiers (emails or samaccountnames)
    users_approved = set(re.findall(r"[a-z0-9._-]+@[a-z0-9.-]+|[a-z0-9._-]+", approved_text, flags=re.I))
    users_adgroup = set(re.findall(r"[a-z0-9._-]+@[a-z0-9.-]+|[a-z0-9._-]+", adgroup_text, flags=re.I))

    missing_in_ad = sorted(users_approved - users_adgroup)
    extra_in_ad = sorted(users_adgroup - users_approved)

    if not missing_in_ad and not extra_in_ad:
        return "Pass", f"Approved={len(users_approved)}, ADGroup={len(users_adgroup)} (match)."
    return "Fail", f"Missing in AD: {missing_in_ad or 'None'}; Extra in AD: {extra_in_ad or 'None'}."

def test_ml1_om_03(text: str):
    """
    Block macros from internet-sourced files (Mark-of-the-Web banner screenshots).
    """
    phrases = [
        "microsoft has blocked macros",
        "blocked because the source is untrusted",
        "macros from the internet have been disabled",
        "blocked macros from running in office files from the internet"
    ]
    ok = grep_any(text, phrases)
    return ok, "Detected block banner for internet-sourced file." if ok else "No banner detected."

def test_ml1_om_04(text: str):
    """
    Registry policy: blockcontentexecutionfromInternet == 1 for each app.
    We accept pass if we see at least one app enforced; ideal is all three.
    """
    apps = ("word", "excel", "powerpoint")
    per_app = {}
    for app in apps:
        val = find_registry_value(
            text,
            rf"software\\policies\\microsoft\\office\\(14\.0|15\.0|16\.0)\\{app}\\security",
            "blockcontentexecutionfrominternet"
        )
        per_app[app] = val

    all_present = all(per_app[a] == 1 for a in apps if per_app[a] is not None)
    any_present = any(per_app[a] == 1 for a in apps)

    if any_present:
        status = "Pass" if all_present else "Partial"
        return status, f"{per_app}"
    else:
        return "Fail", f"{per_app}"

def test_ml1_om_05(text: str):
    """
    Macro runtime scan scope enabled (macroruntimescope in registry).
    Accept 1 or 2 as 'enabled' depending on org policy.
    """
    apps = ("word", "excel", "powerpoint")
    per_app = {}
    for app in apps:
        val = find_registry_value(
            text,
            rf"software\\policies\\microsoft\\office\\(14\.0|15\.0|16\.0)\\{app}\\security",
            "macroruntimescope"
        )
        per_app[app] = val
    enabled_any = any(v in (1, 2) for v in per_app.values() if v is not None)
    if enabled_any:
        # If some are missing we'll call it Partial
        all_enabled = all(v in (1, 2) for v in per_app.values() if v is not None)
        status = "Pass" if all_enabled else "Partial"
        return status, f"{per_app}"
    return "Fail", f"{per_app}"

def test_ml1_om_06(text: str):
    """
    AV detects EICAR macro attempt (screenshots/logs).
    """
    signals = ["eicar", "threat found", "quarantined", "blocked", "virus", "office macro", "vba"]
    ok = grep_any(text, signals)
    return ok, "AV detection (EICAR) present in evidence." if ok else "No AV detection evidence."

def test_ml1_om_07(text: str):
    """
    Users cannot change macro settings (Trust Center locked).
    """
    phrases = [
        "managed by your organization",
        "some settings are managed by your organization",
        "trust center settings are disabled",
        "this setting is managed by your administrator",
        "grayed out", "greyed out"
    ]
    ok = grep_any(text, phrases)
    return ok, "Trust Center locked by policy." if ok else "No lock indicator found."

# -----------------------------
# Runner
# -----------------------------
def main():
    # Preload optional pair files for ML1-OM-02 comparison if present
    approved_path = os.path.join(SCREENSHOTS_DIR, "approved_users.txt")
    adgroup_path = os.path.join(SCREENSHOTS_DIR, "ad_group.txt")
    approved_text = extract_text(approved_path) if os.path.exists(approved_path) else ""
    adgroup_text = extract_text(adgroup_path) if os.path.exists(adgroup_path) else ""

    rows = [("TestID", "Evidence", "Status", "Findings")]

    # ML1-OM-02 is global (set comparison), write one line up-front
    status_02, notes_02 = test_ml1_om_02(approved_text, adgroup_text)
    rows.append(("ML1-OM-02", "approved_users.txt + ad_group.txt", status_02, notes_02))

    # Iterate files for the remaining checks
    for fname in sorted(os.listdir(SCREENSHOTS_DIR)):
        path = os.path.join(SCREENSHOTS_DIR, fname)
        if not (is_image(path) or fname.lower().endswith((".txt", ".reg"))):
            continue

        text = extract_text(path)

        # ML1-OM-01
        ok, notes = test_ml1_om_01(text)
        rows.append(("ML1-OM-01", fname, "Pass" if ok else "Fail", notes))

        # ML1-OM-03
        ok, notes = test_ml1_om_03(text)
        rows.append(("ML1-OM-03", fname, "Pass" if ok else "Fail", notes))

        # ML1-OM-04
        status, notes = test_ml1_om_04(text)
        rows.append(("ML1-OM-04", fname, status, notes))

        # ML1-OM-05
        status, notes = test_ml1_om_05(text)
        rows.append(("ML1-OM-05", fname, status, notes))

        # ML1-OM-06
        ok, notes = test_ml1_om_06(text)
        rows.append(("ML1-OM-06", fname, "Pass" if ok else "Fail", notes))

        # ML1-OM-07
        ok, notes = test_ml1_om_07(text)
        rows.append(("ML1-OM-07", fname, "Pass" if ok else "Fail", notes))

    with open(OUT_CSV, "w", newline="", encoding="utf-8") as f:
        csv.writer(f).writerows(rows)

    print(f"\nMacro scan complete. Report saved as: {OUT_CSV}")

if __name__ == "__main__":
    main()
