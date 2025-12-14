@echo off
cd /d %~dp0\..
python -m pip install -r license_admin_app\requirements.txt
python -m license_admin_app
