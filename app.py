import os
import hmac
import json
import base64
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional, Any, Dict, List

from fastapi import FastAPI, HTTPException, Depends, Header
from pydantic import BaseModel, Field

from sqlalchemy import (
    create_engine, Column, String, DateTime, Integer, ForeignKey, Text,
    select, func, or_, update
)
from sqlalchemy.orm import declarative_base, sessionmaker, relationship

from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


# =========================
# Settings
# =========================
def _env(name: str, default: str = "") -> str:
    return (os.environ.get(name) or default).strip()


DATABASE_URL = _env("DATABASE_URL", "sqlite:///license.db")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)
if DATABASE_URL.startswith("postgresql://") and "+psycopg" not in DATABASE_URL:
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)

ADMIN_USER = _env("ADMIN_USER", "admin")
ADMIN_PASS = _env("ADMIN_PASS", "admin")
KEY_HASH_SECRET = _env("KEY_HASH_SECRET", "change-me-please")

LICENSE_KID = _env("LICENSE_KID", "k1")
LICENSE_SIGNING_PRIVATE_PEM_B64 = _env("LICENSE_SIGNING_PRIVATE_PEM_B64", "")

OFFLINE_GRACE_DAYS = int(_env("OFFLINE_GRACE_DAYS", "7"))
ADMIN_TOKEN_TTL_SECONDS = int(_env("ADMIN_TOKEN_TTL_SECONDS", str(12 * 3600)))  # 12h

LICENSE_PREFIX = _env("LICENSE_PREFIX", "LIC")
LICENSE_RANDOM_LEN = int(_env("LICENSE_RANDOM_LEN", "20"))


# =========================
# DB
# =========================
Base = declarative_base()


class License(Base):
    __tablename__ = "licenses"

    id = Column(String(36), primary_key=True)
    key_hash = Column(String(64), unique=True, nullable=False)
    key_tail = Column(String(12), nullable=False)

    status = Column(String(16), default="active")  # active/revoked/disabled/deleted
    expires_at = Column(DateTime(timezone=True), nullable=False)
    max_activations = Column(Integer, default=1)
    note = Column(Text, default="")

    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    revoked_at = Column(DateTime(timezone=True), nullable=True)

    activations = relationship("Activation", back_populates="license", cascade="all, delete-orphan")


class Activation(Base):
    __tablename__ = "activations"

    id = Column(String(36), primary_key=True)
    license_id = Column(String(36), ForeignKey("licenses.id"), nullable=False)

    machine_id = Column(String(128), nullable=False)

    refresh_token_hash = Column(String(64), nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_checkin_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    revoked_at = Column(DateTime(timezone=True), nullable=True)

    license = relationship("License", back_populates="activations")


def _connect_args_for_url(url: str) -> dict:
    # connect_args passed to DBAPI connect()
    if url.startswith("postgresql://") or url.startswith("postgresql+psycopg://"):
        return {"connect_timeout": 10}
    return {}


engine = create_engine(DATABASE_URL, pool_pre_ping=True, connect_args=_connect_args_for_url(DATABASE_URL))
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def db_sess():
    sess = SessionLocal()
    try:
        yield sess
    finally:
        sess.close()


# =========================
# Helpers
# =========================
def _hmac_hash(secret: str, value: str) -> str:
    return hmac.new(secret.encode("utf-8"), value.encode("utf-8"), digestmod="sha256").hexdigest()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_iso_dt(s: str) -> datetime:
    s = (s or "").strip()
    if not s:
        raise ValueError("empty datetime")
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64url_json(obj: Any) -> str:
    return _b64url(json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))


def _load_private_key() -> Ed25519PrivateKey:
    if not LICENSE_SIGNING_PRIVATE_PEM_B64:
        raise RuntimeError("Missing LICENSE_SIGNING_PRIVATE_PEM_B64 (set it in Render env).")
    pem = base64.b64decode(LICENSE_SIGNING_PRIVATE_PEM_B64)
    key = load_pem_private_key(pem, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise RuntimeError("Private key is not Ed25519")
    return key


def _current_public_key_b64() -> str:
    sk = _load_private_key()
    pk = sk.public_key().public_bytes_raw()
    return base64.b64encode(pk).decode("ascii")


def _sign_jws(payload: Dict[str, Any]) -> str:
    sk = _load_private_key()
    header = {"alg": "EdDSA", "kid": LICENSE_KID, "typ": "JWT"}

    h = _b64url_json(header)
    p = _b64url_json(payload)
    signing_input = f"{h}.{p}".encode("ascii")
    sig = sk.sign(signing_input)
    return f"{h}.{p}.{_b64url(sig)}"


# =========================
# Admin token (simple)
# =========================
serializer = URLSafeTimedSerializer(KEY_HASH_SECRET, salt="admin-token")


def _make_admin_token(username: str) -> str:
    return serializer.dumps({"u": username, "t": int(_now().timestamp())})


def _verify_admin_token(token: str) -> dict:
    try:
        return serializer.loads(token, max_age=ADMIN_TOKEN_TTL_SECONDS)
    except SignatureExpired:
        raise HTTPException(status_code=401, detail="Admin token expired")
    except BadSignature:
        raise HTTPException(status_code=401, detail="Invalid admin token")


def admin_auth(authorization: Optional[str] = Header(default=None)) -> dict:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing admin token")
    token = authorization.split(" ", 1)[1].strip()
    return _verify_admin_token(token)


# =========================
# Schemas
# =========================
class ActivateReq(BaseModel):
    license_key: str
    machine_id: str
    app: Optional[str] = ""
    app_version: Optional[str] = ""
    platform: Optional[str] = ""
    ts: Optional[int] = None


class ActivateResp(BaseModel):
    activation_id: str
    refresh_token: str
    certificate: str
    expires_at: str
    server_time: str


class RefreshReq(BaseModel):
    activation_id: str
    refresh_token: str
    machine_id: str
    ts: Optional[int] = None


class RefreshResp(BaseModel):
    certificate: str
    expires_at: str
    server_time: str


class DeactivateReq(BaseModel):
    activation_id: str
    machine_id: str
    ts: Optional[int] = None


class AdminLoginReq(BaseModel):
    username: str
    password: str


class AdminLoginResp(BaseModel):
    token: str


class AdminCreateLicenseReq(BaseModel):
    days: int = Field(default=30, ge=1, le=3650)
    max_activations: int = Field(default=1, ge=1, le=50)
    note: str = ""
    custom_key: Optional[str] = None


class AdminLicenseItem(BaseModel):
    id: str
    key_tail: str
    status: str
    expires_at: str
    max_activations: int
    activations_count: int
    created_at: str
    note: str = ""


class AdminCreateLicenseResp(BaseModel):
    license_key: str
    license: AdminLicenseItem


class AdminExtendReq(BaseModel):
    days_to_add: int = Field(ge=1, le=3650)


class AdminActivationItem(BaseModel):
    id: str
    machine_id: str
    created_at: str
    last_checkin_at: str
    revoked_at: Optional[str] = None


class AdminUpdateLicenseReq(BaseModel):
    status: Optional[str] = None           # active/revoked/disabled/deleted
    expires_at: Optional[str] = None       # ISO (Z ok)
    max_activations: Optional[int] = None
    note: Optional[str] = None


_ALLOWED_STATUS = {"active", "revoked", "disabled", "deleted"}


# =========================
# App
# =========================
app = FastAPI(title="ToolTongHop License Server (Hybrid)", version="1.0.0")


@app.on_event("startup")
def _startup():
    Base.metadata.create_all(bind=engine)
    _ = _current_public_key_b64()


@app.get("/health")
def health():
    return {"ok": True, "time": _iso(_now())}


@app.get("/v1/public-keys")
def public_keys():
    return {"kid": LICENSE_KID, "public_key_b64": _current_public_key_b64()}


def _license_payload(lic: License, act: Activation) -> Dict[str, Any]:
    return {
        "iss": "tooltonghop-license",
        "kid": LICENSE_KID,
        "license_id": lic.id,
        "activation_id": act.id,
        "machine_id": act.machine_id,
        "iat": int(_now().timestamp()),
        "exp": int(lic.expires_at.timestamp()),
        "offline_grace_days": OFFLINE_GRACE_DAYS,
    }


def _generate_license_key() -> str:
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    return f"{LICENSE_PREFIX}-" + "".join(secrets.choice(alphabet) for _ in range(LICENSE_RANDOM_LEN))


@app.post("/v1/licenses/activate", response_model=ActivateResp)
def activate(req: ActivateReq, sess=Depends(db_sess)):
    key = (req.license_key or "").strip()
    mid = (req.machine_id or "").strip()

    if not key or not mid:
        raise HTTPException(status_code=400, detail="Missing license_key or machine_id")

    key_hash = _hmac_hash(KEY_HASH_SECRET, key)

    lic: License | None = sess.execute(
        select(License).where(License.key_hash == key_hash)
    ).scalar_one_or_none()

    if not lic:
        raise HTTPException(status_code=404, detail="License not found")

    if lic.status != "active":
        raise HTTPException(status_code=403, detail=f"License is {lic.status}")

    if lic.expires_at <= _now():
        raise HTTPException(status_code=403, detail="License expired")

    act: Activation | None = sess.execute(
        select(Activation).where(
            Activation.license_id == lic.id,
            Activation.machine_id == mid,
            Activation.revoked_at.is_(None),
        )
    ).scalar_one_or_none()

    active_count = sess.execute(
        select(func.count(Activation.id)).where(
            Activation.license_id == lic.id,
            Activation.revoked_at.is_(None),
        )
    ).scalar_one()

    if not act:
        if active_count >= lic.max_activations:
            raise HTTPException(status_code=403, detail="Activation limit reached")

        act = Activation(
            id=str(uuid.uuid4()),
            license_id=lic.id,
            machine_id=mid,
            refresh_token_hash="",
            created_at=_now(),
            last_checkin_at=_now(),
        )
        sess.add(act)

    refresh_token = secrets.token_urlsafe(32)
    act.refresh_token_hash = _hmac_hash(KEY_HASH_SECRET, refresh_token)
    act.last_checkin_at = _now()

    sess.commit()

    cert = _sign_jws(_license_payload(lic, act))
    return ActivateResp(
        activation_id=act.id,
        refresh_token=refresh_token,
        certificate=cert,
        expires_at=_iso(lic.expires_at),
        server_time=_iso(_now()),
    )


@app.post("/v1/licenses/refresh", response_model=RefreshResp)
def refresh(req: RefreshReq, sess=Depends(db_sess)):
    aid = (req.activation_id or "").strip()
    token = (req.refresh_token or "").strip()
    mid = (req.machine_id or "").strip()

    if not aid or not token or not mid:
        raise HTTPException(status_code=400, detail="Missing activation_id/refresh_token/machine_id")

    act: Activation | None = sess.execute(
        select(Activation).where(Activation.id == aid)
    ).scalar_one_or_none()

    if not act or act.revoked_at is not None:
        raise HTTPException(status_code=403, detail="Activation revoked or not found")

    if act.machine_id != mid:
        raise HTTPException(status_code=403, detail="Wrong machine_id")

    if act.refresh_token_hash != _hmac_hash(KEY_HASH_SECRET, token):
        raise HTTPException(status_code=401, detail="Invalid refresh_token")

    lic: License | None = sess.execute(
        select(License).where(License.id == act.license_id)
    ).scalar_one_or_none()

    if not lic:
        raise HTTPException(status_code=404, detail="License not found")

    if lic.status != "active":
        raise HTTPException(status_code=403, detail=f"License is {lic.status}")

    if lic.expires_at <= _now():
        raise HTTPException(status_code=403, detail="License expired")

    act.last_checkin_at = _now()
    sess.commit()

    cert = _sign_jws(_license_payload(lic, act))
    return RefreshResp(
        certificate=cert,
        expires_at=_iso(lic.expires_at),
        server_time=_iso(_now()),
    )


@app.post("/v1/licenses/deactivate")
def deactivate(req: DeactivateReq, sess=Depends(db_sess)):
    aid = (req.activation_id or "").strip()
    mid = (req.machine_id or "").strip()
    if not aid or not mid:
        raise HTTPException(status_code=400, detail="Missing activation_id/machine_id")

    act: Activation | None = sess.execute(select(Activation).where(Activation.id == aid)).scalar_one_or_none()
    if not act:
        return {"ok": True}

    if act.machine_id != mid:
        raise HTTPException(status_code=403, detail="Wrong machine_id")

    act.revoked_at = _now()
    sess.commit()
    return {"ok": True}


# =========================
# Admin APIs
# =========================
@app.post("/v1/admin/login", response_model=AdminLoginResp)
def admin_login(req: AdminLoginReq):
    if req.username != ADMIN_USER or req.password != ADMIN_PASS:
        raise HTTPException(status_code=401, detail="Invalid admin credentials")
    return AdminLoginResp(token=_make_admin_token(req.username))


@app.get("/v1/admin/licenses", response_model=List[AdminLicenseItem])
def admin_list_licenses(
    q: str = "",
    include_deleted: bool = False,
    _tok=Depends(admin_auth),
    sess=Depends(db_sess),
):
    q = (q or "").strip()

    stmt = select(License)
    if not include_deleted:
        stmt = stmt.where(License.status != "deleted")

    if q:
        like = f"%{q}%"
        stmt = stmt.where(
            or_(
                License.id.ilike(like),
                License.key_tail.ilike(like),
                License.status.ilike(like),
                License.note.ilike(like),
            )
        )

    stmt = stmt.order_by(License.created_at.desc()).limit(500)
    items: List[License] = list(sess.execute(stmt).scalars().all())

    out: List[AdminLicenseItem] = []
    for lic in items:
        active_count = sess.execute(
            select(func.count(Activation.id)).where(
                Activation.license_id == lic.id,
                Activation.revoked_at.is_(None),
            )
        ).scalar_one()
        out.append(
            AdminLicenseItem(
                id=lic.id,
                key_tail=lic.key_tail,
                status=lic.status,
                expires_at=_iso(lic.expires_at),
                max_activations=lic.max_activations,
                activations_count=int(active_count),
                created_at=_iso(lic.created_at),
                note=lic.note or "",
            )
        )
    return out


@app.post("/v1/admin/licenses", response_model=AdminCreateLicenseResp)
def admin_create_license(req: AdminCreateLicenseReq, _tok=Depends(admin_auth), sess=Depends(db_sess)):
    license_key = (req.custom_key or "").strip() or _generate_license_key()
    key_hash = _hmac_hash(KEY_HASH_SECRET, license_key)

    exists = sess.execute(select(License).where(License.key_hash == key_hash)).scalar_one_or_none()
    if exists:
        raise HTTPException(status_code=409, detail="License already exists")

    lic = License(
        id=str(uuid.uuid4()),
        key_hash=key_hash,
        key_tail=license_key[-8:],
        status="active",
        expires_at=_now() + timedelta(days=int(req.days)),
        max_activations=int(req.max_activations),
        note=req.note or "",
        created_at=_now(),
    )
    sess.add(lic)
    sess.commit()

    item = AdminLicenseItem(
        id=lic.id,
        key_tail=lic.key_tail,
        status=lic.status,
        expires_at=_iso(lic.expires_at),
        max_activations=lic.max_activations,
        activations_count=0,
        created_at=_iso(lic.created_at),
        note=lic.note or "",
    )
    return AdminCreateLicenseResp(license_key=license_key, license=item)


@app.patch("/v1/admin/licenses/{license_id}", response_model=AdminLicenseItem)
def admin_update_license(
    license_id: str,
    req: AdminUpdateLicenseReq,
    _tok=Depends(admin_auth),
    sess=Depends(db_sess),
):
    lic: License | None = sess.execute(select(License).where(License.id == license_id)).scalar_one_or_none()
    if not lic:
        raise HTTPException(status_code=404, detail="License not found")

    if req.status is not None:
        st = req.status.strip().lower()
        if st not in _ALLOWED_STATUS:
            raise HTTPException(status_code=400, detail=f"Invalid status: {st}")
        lic.status = st
        if st == "active":
            lic.revoked_at = None
        else:
            lic.revoked_at = _now()

    if req.expires_at is not None:
        lic.expires_at = _parse_iso_dt(req.expires_at)

    if req.max_activations is not None:
        lic.max_activations = int(req.max_activations)

    if req.note is not None:
        lic.note = req.note or ""

    sess.commit()

    active_count = sess.execute(
        select(func.count(Activation.id)).where(
            Activation.license_id == lic.id,
            Activation.revoked_at.is_(None),
        )
    ).scalar_one()

    return AdminLicenseItem(
        id=lic.id,
        key_tail=lic.key_tail,
        status=lic.status,
        expires_at=_iso(lic.expires_at),
        max_activations=lic.max_activations,
        activations_count=int(active_count),
        created_at=_iso(lic.created_at),
        note=lic.note or "",
    )


@app.delete("/v1/admin/licenses/{license_id}")
def admin_delete_license(
    license_id: str,
    _tok=Depends(admin_auth),
    sess=Depends(db_sess),
):
    lic: License | None = sess.execute(select(License).where(License.id == license_id)).scalar_one_or_none()
    if not lic:
        return {"ok": True}

    now = _now()
    lic.status = "deleted"
    lic.revoked_at = now

    # revoke all active activations
    sess.execute(
        update(Activation)
        .where(Activation.license_id == license_id, Activation.revoked_at.is_(None))
        .values(revoked_at=now)
    )

    sess.commit()
    return {"ok": True}


@app.post("/v1/admin/licenses/{license_id}/revoke")
def admin_revoke_license(license_id: str, _tok=Depends(admin_auth), sess=Depends(db_sess)):
    lic = sess.execute(select(License).where(License.id == license_id)).scalar_one_or_none()
    if not lic:
        raise HTTPException(status_code=404, detail="License not found")

    now = _now()
    lic.status = "revoked"
    lic.revoked_at = now

    acts = sess.execute(
        select(Activation).where(Activation.license_id == lic.id, Activation.revoked_at.is_(None))
    ).scalars().all()
    for a in acts:
        a.revoked_at = now

    sess.commit()
    return {"ok": True}


@app.post("/v1/admin/licenses/{license_id}/extend")
def admin_extend_license(license_id: str, req: AdminExtendReq, _tok=Depends(admin_auth), sess=Depends(db_sess)):
    lic = sess.execute(select(License).where(License.id == license_id)).scalar_one_or_none()
    if not lic:
        raise HTTPException(status_code=404, detail="License not found")

    base = lic.expires_at if lic.expires_at > _now() else _now()
    lic.expires_at = base + timedelta(days=int(req.days_to_add))

    if lic.status != "active":
        lic.status = "active"
        lic.revoked_at = None

    sess.commit()
    return {"ok": True, "expires_at": _iso(lic.expires_at)}


@app.get("/v1/admin/licenses/{license_id}/activations", response_model=List[AdminActivationItem])
def admin_list_activations(license_id: str, _tok=Depends(admin_auth), sess=Depends(db_sess)):
    acts = sess.execute(
        select(Activation).where(Activation.license_id == license_id).order_by(Activation.created_at.desc())
    ).scalars().all()
    return [
        AdminActivationItem(
            id=a.id,
            machine_id=a.machine_id,
            created_at=_iso(a.created_at),
            last_checkin_at=_iso(a.last_checkin_at),
            revoked_at=_iso(a.revoked_at) if a.revoked_at else None,
        )
        for a in acts
    ]


@app.post("/v1/admin/activations/{activation_id}/revoke")
def admin_revoke_activation(activation_id: str, _tok=Depends(admin_auth), sess=Depends(db_sess)):
    act = sess.execute(select(Activation).where(Activation.id == activation_id)).scalar_one_or_none()
    if not act:
        raise HTTPException(status_code=404, detail="Activation not found")
    act.revoked_at = _now()
    sess.commit()
    return {"ok": True}

@app.delete("/v1/admin/activations/{activation_id}")
def admin_delete_activation(activation_id: str, _tok=Depends(admin_auth), sess=Depends(db_sess)):
    act = sess.execute(select(Activation).where(Activation.id == activation_id)).scalar_one_or_none()
    if not act:
        return {"ok": True}  # idempotent
    sess.delete(act)
    sess.commit()
    return {"ok": True}
