# Essential8_scanner

OCR-based misconfiguration scanner for EC&V (Essential Eight & Compliance & Verification).

This tool scans screenshots of system settings (e.g., Windows Features) and detects signs of non-compliance or misconfigurations across selected Essential Eight strategies using OCR and keyword matching.

---

## How It Works

- 📸 You provide screenshots (PNG format) of system configurations.
- 🧠 The script uses **Tesseract OCR** to extract visible text.
- 🛡️ It checks for misconfiguration indicators using keyword rules for each strategy.
- 📄 Outputs findings into a CSV report: `scan_report.csv`.

---

## 🧪 Strategies Supported

1. Patch Applications  
2. User Application Hardening  
3. Restrict Admin Privileges  
4. Office Macros  
5. Patch OS  
6. Application Control  
7. MFA  
8. Backup Strategy

---

## 📁 Folder Structure

essential8_scanner/
├── screenshots/ # Place your PNG screenshots here
├── ocr_test.py # Main Python scanner
├── run_scanner.bat # Double-click to run easily
├── requirements.txt # Python dependencies
└── scan_report.csv # Output file (auto-generated)

Required Installs (once only):
1. Python (should already have this)
      Make sure to tick "Add to PATH" during install

2. Tesseract OCR
      Download: https://github.com/tesseract-ocr/tesseract
      Install Windows installer (scroll down to find .exe)
      Add the install path (e.g. C:\Program Files\Tesseract-OCR) to their System PATH
   
**after all that is installed you can run run it manualy by:**
cd path\to\essential8_scanner
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python ocr_test.py

**or you can double click the run_scanner.bat that i have added just to make it easier**

**for both these options first put your screen shot inside the screenshots/ folder**  **VERY IMPORTANT**

there are example screen shots in there i beleive it will go under options 2 **User ApplicationHardening**

****THINGS TO DO OR ADD LATER FROM MOST IMPORTANT OR VITAL TO OPTIONAL (EXTRA MARKS)****

**HIGH PRIORITY**

1. Improve keyword coverage (per mitigation strategy)
      Add more keywords per strategy. Under stratagy_rules pick your Mitigation Stratagy  (e.g. for "Application Control" include things like “whitelist”, “block EXE”).

2. Strategy-specific CSV report
      Each finding is grouped by the selected mitigation strategy and written into the scan_report.csv file. This helps            teams quickly identify which screenshots are relevant to their assigned strategy and begin drafting mitigation               recommendations accordingly.


**MEDIUM AND LOW PRIORITY**

1. False positive filtering
    Exclude partial matches or accidental detections (e.g. “backup” in a non-security context)
2.Regex for fuzzy/variant matching
    Helps find config terms that show up in inconsistent formats Example "multi factor", "multi_factor", "multi-factor", etc.

3. GUI **I was thinking of using Tkinter but will ask Khan if we should do this or another team to help us with it**




