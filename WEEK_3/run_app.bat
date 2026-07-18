@echo off
REM Launch the Streamlit interface (Windows). Run from the WEEK_3 folder.
cd /d "%~dp0"
streamlit run src\app.py
