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

from time import sleep
from types import TracebackType
from typing import TYPE_CHECKING, Any

import httpx

from soar_sdk.exceptions import ActionFailure

from .auth import get_auth
from .constants import API_V2_RESULT_DATA_QUESTION, DEFAULT_TIMEOUT, INTEGRATION_HEADER

if TYPE_CHECKING:
    from .asset import Asset


class TaniumClient:
    """Thin HTTP client for the Tanium REST API."""

    def __init__(self, asset: Asset, *, verify_ssl: bool | None = None) -> None:
        self._base_url = asset.base_url
        self._verify = asset.verify_server_cert if verify_ssl is None else verify_ssl
        self._integration_header_value = (asset.integration_header_value or "").strip()
        self._auth = get_auth(asset, verify_ssl=self._verify)
        self._client = httpx.Client(
            auth=self._auth,
            verify=self._verify,
            headers=self._base_headers(),
            timeout=DEFAULT_TIMEOUT,
        )

    def __enter__(self) -> TaniumClient:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        self._client.close()

    def _base_headers(self) -> dict[str, str]:
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self._integration_header_value:
            headers[INTEGRATION_HEADER] = self._integration_header_value
        return headers

    def _send(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        try:
            return self._client.request(method, url, **kwargs)
        except httpx.RequestError as e:
            raise ActionFailure(
                f"Error connecting to '{self._base_url}'. Detail: {e}"
            ) from e

    def request_raw(
        self,
        method: str,
        endpoint: str,
        *,
        headers: dict[str, str] | None = None,
        timeout: float | int | None = None,
        **kwargs: Any,
    ) -> httpx.Response:
        if endpoint.startswith(("http://", "https://")):
            raise ValueError(
                "TaniumClient endpoint must be a relative path; "
                "the base URL comes from the asset configuration"
            )

        normalized_endpoint = endpoint if endpoint.startswith("/") else f"/{endpoint}"
        url = f"{self._base_url}{normalized_endpoint}"
        kwargs["timeout"] = timeout if timeout is not None else DEFAULT_TIMEOUT

        if headers:
            merged_headers = self._base_headers()
            merged_headers.update(headers)
            kwargs["headers"] = merged_headers

        return self._send(method, url, **kwargs)

    def request(self, method: str, endpoint: str, **kwargs: Any) -> dict[str, Any]:
        response = self.request_raw(method, endpoint, **kwargs)

        # Tanium 7.3.314.4103: sometimes returns a transient 404 for result_data/question
        # even when the sensor exists. A short sleep and retry resolves it.
        if response.status_code == 404 and API_V2_RESULT_DATA_QUESTION in endpoint:
            sleep(5)
            response = self.request_raw(method, endpoint, **kwargs)

        self._raise_for_status(response)
        try:
            return response.json()
        except Exception as e:
            raise ActionFailure(
                f"Unable to parse JSON response from '{endpoint}': {e}"
            ) from e

    def _raise_for_status(self, response: httpx.Response) -> None:
        if not response.is_error:
            return
        msg = response.text or "Empty response"
        try:
            payload = response.json()
        except ValueError:
            pass
        else:
            if isinstance(payload, dict):
                msg = payload.get("text") or payload.get("message") or msg

        raise ActionFailure(f"Status {response.status_code}: {msg}")


def get_client(asset: Asset, *, verify_ssl: bool | None = None) -> TaniumClient:
    """Create a Tanium API client for an asset."""
    return TaniumClient(asset, verify_ssl=verify_ssl)
