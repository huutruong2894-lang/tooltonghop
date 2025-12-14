@echo off
cd /d %~dp0\..
python -m pip install -r requirements.txt
REM Minimal env for local testing
set DATABASE_URL=sqlite:///license.db
set ADMIN_USER=admin
set ADMIN_PASS=admin
set KEY_HASH_SECRET=change-me
REM Generate keys, then paste LICENSE_SIGNING_PRIVATE_PEM_B64 and LICENSE_KID here or in your shell:
REM python -m license_server.gen_keys --kid k1 --print-env
uvicorn app:app --host 127.0.0.1 --port 8000 --reload
