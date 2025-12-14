import requests

class APIClient:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self.token = None
        self.timeout = 60  # avoid Render/Neon cold-start timeouts

    def _headers(self):
        h = {"Content-Type": "application/json"}
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        return h

    def login(self, username: str, password: str):
        r = requests.post(
            f"{self.base_url}/v1/admin/login",
            json={"username": username, "password": password},
            timeout=self.timeout,
        )
        r.raise_for_status()
        self.token = r.json()["token"]

    def list_licenses(self, q: str = ""):
        r = requests.get(
            f"{self.base_url}/v1/admin/licenses",
            params={"q": q},
            headers=self._headers(),
            timeout=self.timeout,
        )
        r.raise_for_status()
        return r.json()

    def create_license(self, days: int = 30, max_activations: int = 1, note: str = ""):
        r = requests.post(
            f"{self.base_url}/v1/admin/licenses",
            json={"days": days, "max_activations": max_activations, "note": note},
            headers=self._headers(),
            timeout=self.timeout,
        )
        r.raise_for_status()
        return r.json()

    def revoke_license(self, license_id: str):
        r = requests.post(
            f"{self.base_url}/v1/admin/licenses/{license_id}/revoke",
            headers=self._headers(),
            timeout=self.timeout,
        )
        r.raise_for_status()
        return r.json()

    def extend_license(self, license_id: str, days_to_add: int):
        r = requests.post(
            f"{self.base_url}/v1/admin/licenses/{license_id}/extend",
            json={"days_to_add": days_to_add},
            headers=self._headers(),
            timeout=self.timeout,
        )
        r.raise_for_status()
        return r.json()

    def list_activations(self, license_id: str):
        r = requests.get(
            f"{self.base_url}/v1/admin/licenses/{license_id}/activations",
            headers=self._headers(),
            timeout=self.timeout,
        )
        r.raise_for_status()
        return r.json()

    def revoke_activation(self, activation_id: str):
        r = requests.post(
            f"{self.base_url}/v1/admin/activations/{activation_id}/revoke",
            headers=self._headers(),
            timeout=self.timeout,
        )
        r.raise_for_status()
        return r.json()
