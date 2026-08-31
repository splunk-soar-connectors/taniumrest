# Copyright (c) 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from __future__ import annotations

from collections.abc import Generator
from typing import TYPE_CHECKING

import httpx
from soar_sdk.auth import StaticTokenAuth
from soar_sdk.exceptions import ActionFailure

from .constants import API_V2_SESSION_LOGIN, DEFAULT_TIMEOUT, INTEGRATION_HEADER

if TYPE_CHECKING:
    from .asset import Asset


class TaniumSessionAuth(httpx.Auth):
    """httpx.Auth for Tanium's proprietary username/password session login.

    On the first request (or after a 401/403), POSTs credentials to
    /api/v2/session/login to obtain a session ID, then injects it as
    the ``session`` request header.  The session ID is cached in
    ``asset.auth_state`` so it survives across action runs.
    """

    requires_response_body = True

    def __init__(self, asset: Asset, *, verify_ssl: bool | None = None) -> None:
        self._asset = asset
        self._base_url = asset.base_url
        self._username = asset.username
        self._password = asset.password
        self._verify = asset.verify_server_cert if verify_ssl is None else verify_ssl
        self._integration_header_value = (asset.integration_header_value or "").strip()

    def _get_cached_session(self) -> str | None:
        return self._asset.auth_state.get("session_id") or None

    def _login_headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self._integration_header_value:
            headers[INTEGRATION_HEADER] = self._integration_header_value
        return headers

    def _login(self) -> str:
        url = f"{self._base_url}{API_V2_SESSION_LOGIN}"
        try:
            with httpx.Client(verify=self._verify) as client:
                response = client.post(
                    url,
                    headers=self._login_headers(),
                    json={"username": self._username, "password": self._password},
                    timeout=DEFAULT_TIMEOUT,
                )
        except httpx.RequestError as e:
            raise ActionFailure(
                f"Error connecting to '{self._base_url}' during authentication. Detail: {e}"
            ) from e

        if response.status_code >= 400:
            try:
                msg = response.json().get("text") or response.text
            except Exception:
                msg = response.text or "Empty response"
            raise ActionFailure(
                f"Authentication failed. Status {response.status_code}: {msg}"
            )

        try:
            session_id = response.json().get("data", {}).get("session")
        except Exception as e:
            raise ActionFailure(
                "Unable to parse authentication response from Tanium"
            ) from e
        if not session_id:
            raise ActionFailure("Failed to obtain session token from Tanium")

        self._asset.auth_state["session_id"] = session_id
        return session_id

    def auth_flow(
        self, request: httpx.Request
    ) -> Generator[httpx.Request, httpx.Response]:
        request.headers["session"] = self._get_cached_session() or self._login()
        response = yield request

        if response.status_code in (401, 403):
            request.headers["session"] = self._login()
            yield request


def get_auth(asset: Asset, *, verify_ssl: bool | None = None) -> httpx.Auth:
    """Return the appropriate httpx.Auth for the asset's credentials."""
    if asset.api_token:
        return StaticTokenAuth(asset.api_token, token_type="", header_name="session")
    if asset.username and asset.password:
        return TaniumSessionAuth(asset, verify_ssl=verify_ssl)
    raise ActionFailure(
        "Please provide either an API token, or username and password credentials"
    )
