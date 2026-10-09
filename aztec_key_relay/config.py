"""Service configuration via pydantic-settings (.env / environment)."""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # ── Upstream (Firebase) — the official app's public identifiers ──────────
    firebase_project_id: str = "PROJECT_ID"
    firebase_app_id: str = "APP_ID"
    firebase_api_key: str = "API_KEY"
    firebase_android_package: str = "ANDROID_PACKAGE"
    firebase_android_cert: str = "ANDROID_CERT"
    firebase_rc_sdk_version: str = "23.0.0"
    firebase_app_build: str = "APP_BUILD"

    # ── Service behaviour ────────────────────────────────────────────────────
    relay_api_token: str | None = None
    relay_min_fetch_interval: int = Field(default=60, ge=0)
    relay_daily_refresh_hour: int = Field(default=4, ge=0, le=23)
    relay_db_path: str = "data/state.db"
    relay_key_history: int = Field(default=10, ge=1)

    @property
    def installations_url(self) -> str:
        return f"https://firebaseinstallations.googleapis.com/v1/projects/{self.firebase_project_id}/installations"

    @property
    def remote_config_url(self) -> str:
        return f"https://firebaseremoteconfig.googleapis.com/v1/projects/{self.firebase_project_id}/namespaces/firebase:fetch"


@lru_cache
def get_settings() -> Settings:
    return Settings()
