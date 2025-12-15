from __future__ import annotations

import requests
from typing import Any, Dict, Optional, List


class APIClient:
    def __init__(self, base_url: str):
        self.base_url = (base_url or "").rstrip("/")
        self.token: Optional[str] = None
        # Render/Neon hay cold-start, để timeout dài hơn chút
        self.timeout: float = 60.0

    def set_base_url(self, base_url: str):
        self.base_url = (base_url or "").rstrip("/")

    def _headers(self) -> Dict[str, str]:
        h = {"Content-Type": "application/json"}
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        return h

    def _url(self, path: str) -> str:
        if not path.startswith("/"):
            path = "/" + path
        return f"{self.base_url}{path}"

    # =========================
    # Admin auth
    # =========================
    def login(self, username: str, password: str) -> str:
        r = requests.post(
            self._url("/v1/admin/login"),
            json={"username": username, "password": password},
            timeout=self.timeout,
        )
        r.raise_for_status()
        data = r.json()
        self.token = data["token"]
        return self.token

    # =========================
    # Licenses
    # =========================
    def list_licenses(self, q: str = "", include_deleted: bool = False) -> List[Dict[str, Any]]:
        r = requests.get(
            self._url("/v1/admin/licenses"),
            params={"q": q or "", "include_deleted": "true" if include_deleted else "false"},
            headers=self._headers(),
            timeout=self.timeout,
        )
        r.raise_for_status()
        data = r.json()
        if not isinstance(data, list):
            raise RuntimeError(f"Unexpected response (expected list): {data}")
        return data

    def create_license(
        self,
        days: int = 30,
        max_activations: int = 1,
        note: str = "",
        custom_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "days": int(days),
            "max_activations": int(max_activations),
            "note": note or "",
        }
        if custom_key:
            payload["custom_key"] = custom_key

        r = requests.post(
            self._url("/v1/admin/licenses"),
            json=payload,
            headers=self._headers(),
            timeout=self.timeout,
        )
        r.raise_for_status()
        return r.json()

    def update_license(
        self,
        license_id: str,
        *,
        status: Optional[str] = None,
        expires_at: Optional[str] = None,
        max_activations: Optional[int] = None,
        note: Optional[str] = None,
    ) -> Dict[str, Any]:
        body: Dict[str, Any] = {}
        if status is not None:
            body["status"] = status
        if expires_at is not None:
            body["expires_at"] = expires_at
        if max_activations is not None:
            body["max_activations"] = int(max_activations)
        if note is not None:
            body["note"] = note

        r = requests.patch(
            self._url(f"/v1/admin/licenses/{license_id}"),
            json=body,
            headers=self._headers(),
            timeout=self.timeout,
        )
        r.raise_for_status()
        return r.json()

    def delete_license(self, license_id: str) -> Dict[str, Any]:
        r = requests.delete(
            self._url(f"/v1/admin/licenses/{license_id}"),
            headers=self._headers(),
            timeout=self.timeout,
        )
        r.raise_for_status()
        return r.json()

    def revoke_license(self, license_id: str) -> Dict[str, Any]:
        r = requests.post(
            self._url(f"/v1/admin/licenses/{license_id}/revoke"),
            headers=self._headers(),
            timeout=self.timeout,
        )
        r.raise_for_status()
        return r.json()

    def extend_license(self, license_id: str, days_to_add: int) -> Dict[str, Any]:
        r = requests.post(
            self._url(f"/v1/admin/licenses/{license_id}/extend"),
            json={"days_to_add": int(days_to_add)},
            headers=self._headers(),
            timeout=self.timeout,
        )
        r.raise_for_status()
        return r.json()

    # =========================
    # Activations
    # =========================
    def list_activations(self, license_id: str) -> List[Dict[str, Any]]:
        r = requests.get(
            self._url(f"/v1/admin/licenses/{license_id}/activations"),
            headers=self._headers(),
            timeout=self.timeout,
        )
        r.raise_for_status()
        data = r.json()
        if not isinstance(data, list):
            raise RuntimeError(f"Unexpected response (expected list): {data}")
        return data

    def revoke_activation(self, activation_id: str) -> Dict[str, Any]:
        r = requests.post(
            self._url(f"/v1/admin/activations/{activation_id}/revoke"),
            headers=self._headers(),
            timeout=self.timeout,
        )
        r.raise_for_status()
        return r.json()
