# ToolTongHop - Hybrid License Server (Render + Neon)

## 1) Local run
```bat
python -m pip install -r requirements.txt
set DATABASE_URL=sqlite:///license.db
set ADMIN_USER=admin
set ADMIN_PASS=admin
set KEY_HASH_SECRET=change-me
set LICENSE_KID=k1
REM Generate keys -> set LICENSE_SIGNING_PRIVATE_PEM_B64
python -m license_server.gen_keys --kid k1 --print-env
```

Then run:
```bat
uvicorn app:app --host 127.0.0.1 --port 8000 --reload
```

Open:
- http://127.0.0.1:8000/health
- http://127.0.0.1:8000/docs

## 2) Render deploy
Build:
- `pip install -r requirements.txt`

Start:
- `uvicorn app:app --host 0.0.0.0 --port $PORT`

ENV required:
- DATABASE_URL (Neon connection string; remove leading `psql` and quotes, prefer `postgresql://...`)
- ADMIN_USER, ADMIN_PASS
- KEY_HASH_SECRET
- LICENSE_KID
- LICENSE_SIGNING_PRIVATE_PEM_B64
- OFFLINE_GRACE_DAYS=7 (optional)

Endpoints (match tool's `core/license_manager.py`):
- GET  /health
- GET  /v1/public-keys  -> {kid, public_key_b64}
- POST /v1/licenses/activate
- POST /v1/licenses/refresh
- POST /v1/licenses/deactivate

Admin API:
- POST /v1/admin/login
- GET/POST /v1/admin/licenses
- POST /v1/admin/licenses/{id}/extend
- POST /v1/admin/licenses/{id}/revoke
- GET /v1/admin/licenses/{id}/activations
- POST /v1/admin/activations/{id}/revoke

Tip (Neon):
- If you copied a `psql 'postgresql://...` snippet, remove `psql` and the surrounding quotes.
- If connection fails, try removing `&channel_binding=require` from DATABASE_URL.
