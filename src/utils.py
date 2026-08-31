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
from copy import deepcopy
from typing import Any

from soar_sdk.exceptions import ActionFailure


def normalize_result_data(response: dict[str, Any]) -> dict[str, Any]:
    normalized_response = deepcopy(response)
    result_sets = normalized_response.get("data", {}).get("result_sets", [])
    if not result_sets or not result_sets[0].get("columns"):
        return normalized_response

    for row in result_sets[0].get("rows", []):
        formatted = []
        for values in row.get("data", []):
            first_value = dict(values[0]) if values else {}
            first_value["entries"] = values
            formatted.append(first_value)
        row["data"] = formatted
    return normalized_response


def get_response_data(response_data: Any, resource_name: str) -> dict[str, Any]:
    if isinstance(response_data, list):
        if len(response_data) != 1:
            raise ActionFailure(
                f"Expected one {resource_name}, got {len(response_data)}"
            )
        item = response_data[0]
    elif isinstance(response_data, dict):
        item = response_data
    else:
        raise ActionFailure(f"Unexpected API response for {resource_name}")
    if not isinstance(item, dict):
        raise ActionFailure(f"Unexpected API response for {resource_name}")
    return item
