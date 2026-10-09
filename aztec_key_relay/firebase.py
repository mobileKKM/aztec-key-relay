"""Firebase upstream client: one shared Installation + the RC `:fetch` call.

Replicates what the official mKKM client does (Hermes module 1775):
`remoteConfig.fetch() → activate() → getValue('aztecKey')`. The REST flow
underneath needs a Firebase Installation identifier (FID) and an FIS auth
token, which we create **once** and persist — that's the whole privacy point
of this service: end-user devices never contact Google, and there is a
single shared installation instead of one per app install.

Endpoint shapes (observed on the wire, see mobile_kkm's ekp_crypto README):

* ``POST /v1/projects/{p}/installations`` →
  ``{"fid": "…22 hex…", "refreshToken": "…", "expiresIn": "1w"}``
* ``POST /v1/projects/{p}/installations/{fid}/authTokens:generate`` →
  ``{"token": "…", "expiresIn": "604800s"}``
* ``POST /v1/projects/{p}/namespaces/firebase:fetch`` →
  ``{"state": "UPDATE", "entries": {"aztecKey": "<PEM>", …}}``
"""

from __future__ import annotations

import secrets
import string
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx

from .config import Settings

INSTALLATIONS_TIMEOUT = httpx.Timeout(10.0, read=20.0)
REMOTE_CONFIG_TIMEOUT = httpx.Timeout(10.0, read=20.0)


class FirebaseError(RuntimeError):
    """An upstream Firebase call failed (network, HTTP or bad payload)."""


@dataclass(slots=True)
class AuthToken:
    token: str
    expires_at: datetime


@dataclass(slots=True)
class Installation:
    fid: str
    refresh_token: str
    auth: AuthToken | None = None


def _parse_duration(value: str) -> timedelta:
    """Parses Go-style durations: ``604800s``, ``1w``, ``0.5h`` …"""
    import re

    match = re.fullmatch(r"(?P<n>[\d.]+)(?P<u>[smhdw])", value.strip())
    if not match:
        raise ValueError(f"unparseable duration: {value!r}")
    unit = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}[match.group("u")]
    return timedelta(seconds=float(match.group("n")) * unit)


class FirebaseClient:
    """Stateful client owning the shared Firebase Installation."""

    def __init__(self, settings: Settings, client: httpx.AsyncClient) -> None:
        self._settings = settings
        self._http = client
        self._installation: Installation | None = None

    @property
    def installation(self) -> Installation | None:
        return self._installation

    def restore_installation(self, fid: str, refresh_token: str) -> None:
        """Adopts a persisted installation (no network traffic)."""
        self._installation = Installation(fid=fid, refresh_token=refresh_token)

    def _new_fid(self) -> str:
        # FIDs must match ^[cdef][\w-]{21}$ — the first char encodes a 2-bit
        # version (firebase-js-sdk's generateFid); anything else gets HTTP 400.
        alphabet = string.ascii_letters + string.digits + "-_"
        return secrets.choice("cdef") + "".join(secrets.choice(alphabet) for _ in range(21))

    async def _post(self, url: str, *, headers: dict[str, str], json: dict[str, Any] | None = None) -> dict[str, Any]:
        try:
            response = await self._http.post(url, headers=headers, json=json)
        except httpx.HTTPError as exc:
            raise FirebaseError(f"network error calling {url}: {exc}") from exc
        if response.status_code != 200:
            raise FirebaseError(f"{url} returned HTTP {response.status_code}: {response.text[:200]}")
        try:
            return response.json()
        except ValueError as exc:
            raise FirebaseError(f"{url} returned non-JSON body") from exc

    def _android_headers(self) -> dict[str, str]:
        """Identity headers required by the Android-restricted API key."""
        return {
            "X-Android-Package": self._settings.firebase_android_package,
            "X-Android-Cert": self._settings.firebase_android_cert,
        }

    async def _create_installation(self) -> Installation:
        assert self._installation is None
        fid = self._new_fid()
        data = await self._post(
            self._settings.installations_url,
            headers={
                "X-Goog-Api-Key": self._settings.firebase_api_key,
                "Content-Type": "application/json",
                **self._android_headers(),
            },
            json={
                "fid": fid,
                "appId": self._settings.firebase_app_id,
                "authVersion": "FIS_v2",
            },
        )
        if not data.get("fid") or not data.get("refreshToken"):
            raise FirebaseError(f"installations response missing fid/refreshToken: {sorted(data)}")
        return Installation(fid=data["fid"], refresh_token=data["refreshToken"])

    async def _generate_auth_token(self, installation: Installation) -> AuthToken:
        url = f"{self._settings.installations_url}/{installation.fid}/authTokens:generate"
        data = await self._post(
            url,
            headers={
                "Authorization": f"FIS_v2 {installation.refresh_token}",
                "X-Goog-Api-Key": self._settings.firebase_api_key,
                "Content-Type": "application/json",
                **self._android_headers(),
            },
            json={},
        )
        token = data.get("token")
        expires = data.get("expiresIn")
        if not token or not expires:
            raise FirebaseError(f"authTokens:generate response missing token/expiresIn: {sorted(data)}")
        try:
            ttl = _parse_duration(expires)
        except ValueError as exc:
            raise FirebaseError(str(exc)) from exc
        return AuthToken(token=token, expires_at=datetime.now(UTC) + ttl)

    async def ensure_installation(self) -> Installation:
        """Returns a valid installation, creating or re-authing as needed."""
        if self._installation is None:
            self._installation = await self._create_installation()
            # New installations get their token with the first authenticated call;
            # generate one eagerly so persisting saves a complete record.
            self._installation.auth = await self._generate_auth_token(self._installation)
            return self._installation

        auth = self._installation.auth
        if auth is None or auth.expires_at <= datetime.now(UTC) + timedelta(minutes=5):
            self._installation.auth = await self._generate_auth_token(self._installation)
        return self._installation

    async def fetch_aztec_key(self) -> str:
        """Fetches the RC template and returns the raw `aztecKey` value.

        Refreshes the installation/auth token if needed (retrying once with a
        fresh installation when the FID was invalidated server-side).
        """
        for attempt in (0, 1):
            installation = await self.ensure_installation()
            assert installation.auth is not None
            try:
                data = await self._post(
                    self._settings.remote_config_url,
                    headers={
                        "X-Goog-Api-Key": self._settings.firebase_api_key,
                        "X-Android-Package": self._settings.firebase_android_package,
                        "X-Android-Cert": self._settings.firebase_android_cert,
                        "X-Goog-Firebase-Installations-Auth": installation.auth.token,
                        "X-Google-Signal-Key-Token": self._settings.firebase_api_key,
                        "Content-Type": "application/json",
                        "Accept": "application/json",
                    },
                    json={
                        "appInstanceId": installation.fid,
                        "appId": self._settings.firebase_app_id,
                        "sdkVersion": self._settings.firebase_rc_sdk_version,
                        "appBuild": self._settings.firebase_app_build,
                    },
                )
            except FirebaseError:
                # A revoked FID (server prunes idle installations) manifests as
                # auth failure — start over with a fresh installation once.
                if attempt == 0:
                    self._installation = None
                    continue
                raise

            entries = data.get("entries")
            if not isinstance(entries, dict):
                # NO_TEMPLATE / empty first-time response — treat as missing key.
                raise FirebaseError(f"RC fetch response has no entries (state={data.get('state')!r})")
            value = entries.get("aztecKey")
            if not isinstance(value, str) or not value.strip():
                raise FirebaseError(f"RC entries missing aztecKey: {sorted(entries)}")
            return value

        raise FirebaseError("unreachable")
