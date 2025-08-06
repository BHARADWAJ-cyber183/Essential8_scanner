@echo off
cd /d %~dp0
call venv\Scripts\activate.bat
python ocr_test.py
pause
