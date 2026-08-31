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
import json

import httpx
from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import MakeRequestOutput
from soar_sdk.exceptions import ActionFailure
from soar_sdk.params import MakeRequestParams, Param

from ..asset import Asset
from ..tanium_client import get_client


class TaniumMakeRequestParams(MakeRequestParams):
    endpoint: str = Param(
        description=(
            "Tanium REST API endpoint, relative to the base URL. "
            "Example: '/api/v2/saved_questions' or '/api/v2/sensors/by-name/IP%20Address'"
        ),
        required=True,
        primary=True,
    )
    verify_ssl: bool | None = Param(
        description=(
            "Whether to verify the SSL certificate. Defaults to the asset's "
            "'Verify Server Certificate' setting."
        ),
        required=False,
        default=None,
    )


def make_request(
    params: TaniumMakeRequestParams, soar: SOARClient, asset: Asset
) -> MakeRequestOutput:
    """Make a generic HTTP request to the Tanium REST API."""
    if params.endpoint.startswith(("http://", "https://")):
        raise ActionFailure(
            f"Invalid endpoint '{params.endpoint}'. "
            "Provide a relative path only (e.g. '/api/v2/saved_questions'). "
            "The base URL is taken from the asset configuration."
        )

    endpoint = (
        params.endpoint if params.endpoint.startswith("/") else f"/{params.endpoint}"
    )

    extra_headers: dict = {}
    if params.headers:
        try:
            extra_headers = json.loads(params.headers)
        except (json.JSONDecodeError, TypeError) as e:
            raise ActionFailure(f"Invalid JSON in 'headers' parameter: {e}") from e
        if not isinstance(extra_headers, dict):
            raise ActionFailure("'headers' parameter must be a JSON object")

    query_params = None
    if params.query_parameters:
        try:
            query_params = json.loads(params.query_parameters)
        except (json.JSONDecodeError, TypeError):
            query_params = params.query_parameters.removeprefix("?")

    json_body = None
    raw_body = None
    if params.body:
        content_type = (
            httpx.Headers(extra_headers).get("Content-Type", "application/json").lower()
        )
        if "json" in content_type:
            try:
                json_body = json.loads(params.body)
            except (json.JSONDecodeError, TypeError) as e:
                raise ActionFailure(f"Invalid JSON in 'body' parameter: {e}") from e
        else:
            raw_body = params.body

    timeout = params.timeout or 30

    with get_client(asset, verify_ssl=params.verify_ssl) as client:
        response = client.request_raw(
            params.http_method,
            endpoint,
            params=query_params,
            headers=extra_headers,
            json=json_body,
            content=raw_body,
            timeout=timeout,
        )

    return MakeRequestOutput(
        status_code=response.status_code,
        response_body=response.text,
    )
