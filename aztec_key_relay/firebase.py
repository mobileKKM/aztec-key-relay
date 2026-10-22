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

import json
import re
import secrets
import string
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx

from .config import Settings

# authTokens:generate statuses meaning "this FID is gone" — the Firebase SDK
# deletes the installation and registers a new one on exactly these.
_INSTALLATION_INVALID_STATUSES = frozenset({401, 403, 404})


class FirebaseError(RuntimeError):
    """An upstream Firebase call failed (network, HTTP or bad payload)."""

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class InstallationInvalidError(FirebaseError):
    """The installation was revoked or never existed server-side."""


class TemplateUnchangedError(FirebaseError):
    """The RC template is unchanged — real HTTP 304, or the observed
    HTTP 200 + ``{"state": "NO_CHANGE"}`` revalidation response.

    Not a failure: callers should keep serving their cached key (this mirrors
    the official client's fetch → activate fallback to persisted values).
    """

    def __init__(self) -> None:
        super().__init__("RC template unchanged (304 / NO_CHANGE)")


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
    match = re.fullmatch(r"(?P<n>[\d.]+)(?P<u>[smhdw])", value.strip())
    if not match:
        raise ValueError(f"unparseable duration: {value!r}")
    unit = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}[match.group("u")]
    return timedelta(seconds=float(match.group("n")) * unit)


class FirebaseClient:
    """Stateful client owning the shared Firebase Installation.

    Upstream fidelity: the header set and JSON body replicate the official
    client's requests byte-for-byte where captured (User-Agent/Accept absent,
    `Accept-Encoding: gzip`, `Connection: Keep-Alive`, compact
    `JSONObject.toString()`-style bodies with `/` escaped, ETag revalidation)
    — a Python-identifiable fingerprint would otherwise stick out.
    """

    def __init__(self, settings: Settings, client: httpx.AsyncClient) -> None:
        self._settings = settings
        self._http = client
        self._installation: Installation | None = None
        # The ETag we revalidate with, and the one from the last fetch that
        # the caller has not accepted yet (see commit_etag).
        self._rc_etag: str | None = None
        self._pending_etag: str | None = None

    @property
    def installation(self) -> Installation | None:
        return self._installation

    def restore_installation(
        self,
        fid: str,
        refresh_token: str,
        auth_token: str | None = None,
        auth_expires_at: datetime | None = None,
    ) -> None:
        """Adopts a persisted installation (no network traffic)."""
        auth = AuthToken(auth_token, auth_expires_at) if auth_token and auth_expires_at else None
        self._installation = Installation(fid=fid, refresh_token=refresh_token, auth=auth)

    def commit_etag(self) -> None:
        """Revalidate future fetches against the last fetched template.

        Call only once the fetched key was validated and stored — otherwise
        a rejected key would come back as "304 unchanged" next time.
        """
        if self._pending_etag:
            self._rc_etag = self._pending_etag
        self._pending_etag = None

    def clear_etag(self) -> None:
        """Forget the ETag so the next fetch returns the full template."""
        self._rc_etag = None
        self._pending_etag = None

    def _new_fid(self) -> str:
        # FIDs must match ^[cdef][\w-]{21}$ — the first char encodes a 2-bit
        # version (firebase-js-sdk's generateFid); anything else gets HTTP 400.
        alphabet = string.ascii_letters + string.digits + "-_"
        return secrets.choice("cdef") + "".join(secrets.choice(alphabet) for _ in range(21))

    async def _post(self, url: str, *, headers: dict[str, str], content: bytes) -> tuple[dict[str, Any], httpx.Headers]:
        try:
            response = await self._http.post(url, headers=headers, content=content)
        except httpx.HTTPError as exc:
            raise FirebaseError(f"network error calling {url}: {exc!r}") from exc
        if response.status_code == 304:
            # ETag revalidation hit — no body. Callers treat this as "unchanged".
            return {}, response.headers
        if response.status_code != 200:
            raise FirebaseError(
                f"{url} returned HTTP {response.status_code}: {response.text[:200]}", status_code=response.status_code
            )
        try:
            return response.json(), response.headers
        except ValueError as exc:
            raise FirebaseError(f"{url} returned non-JSON body") from exc

    def _android_headers(self) -> dict[str, str]:
        """Identity headers required by the Android-restricted API key."""
        return {
            "X-Android-Package": self._settings.firebase_android_package,
            "X-Android-Cert": self._settings.firebase_android_cert,
        }

    @staticmethod
    def _sdk_headers(ua: str | None = None) -> dict[str, str]:
        """Transport headers of the SDK's OkHttp stack, per the capture:
        Dalvik UA, `Connection: Keep-Alive`, `Accept-Encoding: gzip` — and
        no httpx defaults leaking (python-httpx UA, 'gzip, deflate').
        """
        headers = {"Accept-Encoding": "gzip", "Connection": "Keep-Alive"}
        if ua:
            headers["User-Agent"] = ua
        return headers

    @staticmethod
    def _sdk_json_body(fields: dict[str, Any]) -> bytes:
        """Serializes like Android's `JSONObject.toString()` — compact and with
        `/` escaped (the capture shows `Europe\\/Warsaw`). httpx's `json=` uses
        a space after separators (", ") — different bytes, so we build it ourselves.
        """
        return json.dumps(fields, separators=(",", ":"), ensure_ascii=False).replace("/", "\\/").encode()

    async def _fetch_rc(self, installation: Installation) -> tuple[dict[str, Any], httpx.Headers]:
        # Header set replicated 1:1 from the captured official-app fetch
        # (both cache-miss and cache-hit variants; 2026-09-30/10-08 captures).
        headers = {
            "X-Goog-Api-Key": self._settings.firebase_api_key,
            "X-Android-Package": self._settings.firebase_android_package,
            "X-Android-Cert": self._settings.firebase_android_cert,
            "X-Google-GFE-Can-Retry": "yes",
            "X-Goog-Firebase-Installations-Auth": installation.auth.token,
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-Firebase-RC-Fetch-Type": "BASE/1",
            "User-Agent": self._settings.firebase_user_agent,
            **self._sdk_headers(),
        }
        if self._rc_etag:
            headers["If-None-Match"] = self._rc_etag
        return await self._post(
            self._settings.remote_config_url,
            headers=headers,
            content=self._sdk_json_body(
                {
                    "appInstanceId": installation.fid,
                    "appVersion": self._settings.firebase_app_version,
                    "countryCode": self._settings.firebase_country_code,
                    "analyticsUserProperties": {},
                    "appId": self._settings.firebase_app_id,
                    "platformVersion": self._settings.firebase_platform_version,
                    "timeZone": self._settings.firebase_time_zone,
                    "sdkVersion": self._settings.firebase_rc_sdk_version,
                    "packageName": self._settings.firebase_android_package,
                    "appInstanceIdToken": installation.auth.token,
                    "languageCode": self._settings.firebase_language_code,
                    "appBuild": self._settings.firebase_app_build,
                }
            ),
        )

    async def _create_installation(self) -> Installation:
        assert self._installation is None
        fid = self._new_fid()
        data, _ = await self._post(
            self._settings.installations_url,
            headers={
                "Content-Type": "application/json",
                # Set explicitly so httpx's default `Accept: */*` never goes out;
                # the FIS Android SDK sends application/json.
                "Accept": "application/json",
                "X-Goog-Api-Key": self._settings.firebase_api_key,
                **self._android_headers(),
                **self._sdk_headers(self._settings.firebase_user_agent),
            },
            content=self._sdk_json_body({"fid": fid, "appId": self._settings.firebase_app_id, "authVersion": "FIS_v2"}),
        )
        if not data.get("fid") or not data.get("refreshToken"):
            raise FirebaseError(f"installations response missing fid/refreshToken: {sorted(data)}")
        return Installation(fid=data["fid"], refresh_token=data["refreshToken"])

    async def _generate_auth_token(self, installation: Installation) -> AuthToken:
        url = f"{self._settings.installations_url}/{installation.fid}/authTokens:generate"
        try:
            data, _ = await self._post(
                url,
                headers={
                    "Authorization": f"FIS_v2 {installation.refresh_token}",
                    "Content-Type": "application/json",
                    # Set explicitly so httpx's default `Accept: */*` never goes out;
                    # the FIS Android SDK sends application/json.
                    "Accept": "application/json",
                    "X-Goog-Api-Key": self._settings.firebase_api_key,
                    **self._android_headers(),
                    **self._sdk_headers(self._settings.firebase_user_agent),
                },
                # The endpoint rejects any body fields ("Unknown name …") — the
                # official SDK sends an empty JSON object.
                content=b"{}",
            )
        except FirebaseError as exc:
            if exc.status_code in _INSTALLATION_INVALID_STATUSES:
                raise InstallationInvalidError(str(exc), status_code=exc.status_code) from exc
            raise
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

        Refreshes the auth token if needed and revalidates with the committed
        ETag like the official client. Only a revoked/unknown installation
        (401/403/404 from authTokens:generate) is replaced by a fresh one —
        network errors and 5xx keep the shared installation, so a flaky
        upstream never multiplies our footprint. An RC 401/403 regenerates
        the auth token once.

        On a 304 (template unchanged) raises [TemplateUnchangedError] —
        callers keep their cached key, like the official client. After a
        successful return, the new ETag is pending until [commit_etag].
        """
        self._pending_etag = None
        for attempt in (0, 1):
            try:
                installation = await self.ensure_installation()
            except InstallationInvalidError:
                if attempt == 0:
                    self._installation = None
                    continue
                raise
            try:
                data, resp_headers = await self._fetch_rc(installation)
            except FirebaseError as exc:
                if attempt == 0 and exc.status_code in (401, 403):
                    installation.auth = None  # stale token — mint a new one
                    continue
                raise

            entries = data.get("entries")
            if not isinstance(entries, dict):
                # Revalidation hit — either a real HTTP 304 (empty body) or the
                # observed HTTP 200 + {"state": "NO_CHANGE"} shape.
                if not data or data.get("state") == "NO_CHANGE":
                    raise TemplateUnchangedError
                raise FirebaseError(f"RC fetch response has no entries (state={data.get('state')!r})")
            value = entries.get("aztecKey")
            if not isinstance(value, str) or not value.strip():
                raise FirebaseError(f"RC entries missing aztecKey: {sorted(entries)}")
            self._pending_etag = resp_headers.get("ETag")
            return value

        raise FirebaseError("unreachable")
