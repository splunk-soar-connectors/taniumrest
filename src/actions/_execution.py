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
import ast
import json
from typing import Any

from soar_sdk.exceptions import ActionFailure

from ..constants import (
    API_V2_SAVED_ACTIONS,
    endpoint_action_group_by_name,
    endpoint_group_by_name,
    endpoint_package_by_name,
)
from ..tanium_client import TaniumClient
from ..utils import get_response_data

_PARAMETERS_WITHOUT_INPUT = frozenset(
    [
        "com.tanium.components.parameters::SeparatorParameter",
    ]
)


def validate_action_params(
    expire_seconds: int,
    distribute_seconds: int | None,
    issue_seconds: int | None,
) -> None:
    if expire_seconds <= 0:
        raise ActionFailure(
            "Please provide a valid non-zero non-negative integer value in the 'expire_seconds' action parameter"
        )
    if distribute_seconds is not None and distribute_seconds < 0:
        raise ActionFailure(
            "Please provide a valid non-negative integer value in the 'distribute_seconds' action parameter"
        )
    if issue_seconds is not None and issue_seconds <= 0:
        raise ActionFailure(
            "Please provide a valid non-zero non-negative integer value in the 'issue_seconds' action parameter"
        )


def run_action(
    client: TaniumClient,
    action_name: str,
    action_group: str,
    package_name: str,
    expire_seconds: int,
    package_parameters: str | None = None,
    group_name: str | None = None,
    distribute_seconds: int | None = None,
    issue_seconds: int | None = None,
) -> dict[str, Any]:
    pkg_response = client.request("GET", endpoint_package_by_name(package_name))
    pkg_data = pkg_response.get("data")
    if not pkg_data:
        raise ActionFailure(f"No package exists with name '{package_name}'")
    pkg = get_response_data(pkg_data, "package")

    raw_pd = pkg.get("parameter_definition")
    parameter_definition: dict[str, Any] | None = None
    if raw_pd:
        try:
            parameter_definition = (
                json.loads(raw_pd) if not isinstance(raw_pd, dict) else raw_pd
            )
        except Exception as e:
            raise ActionFailure(
                f"Error parsing package parameter_definition: {e}"
            ) from e

    package_param: list[dict[str, Any]] = []
    if parameter_definition and parameter_definition.get("parameters"):
        count_required = sum(
            1
            for p in parameter_definition["parameters"]
            if p.get("parameterType") not in _PARAMETERS_WITHOUT_INPUT
        )
        if count_required > 0:
            if package_parameters is None:
                raise ActionFailure(
                    "Please provide the required package parameter in the following format: "
                    '{"<key_1>": "<value_1>", "<key_2>": "<value_2>"}'
                )
            try:
                parsed_params = json.loads(package_parameters)
            except Exception as e:
                raise ActionFailure(f"Error parsing 'package_parameters': {e}") from e

            if not isinstance(parsed_params, dict):
                raise ActionFailure("'package_parameters' must be a JSON object")

            if len(parsed_params) != count_required:
                raise ActionFailure(
                    "Please provide all the required package parameters in 'package_parameters'"
                )
            valid_keys = {p.get("key") for p in parameter_definition["parameters"]}
            invalid = [k for k in parsed_params if k not in valid_keys]
            if invalid:
                raise ActionFailure(
                    f"The following key(s) are incorrect: {', '.join(invalid)}. Please provide correct key(s)"
                )
            package_param = [{"key": k, "value": v} for k, v in parsed_params.items()]

    package_spec: dict[str, Any] = {"source_id": pkg.get("id")}
    if package_param:
        package_spec["parameters"] = package_param

    data: dict[str, Any] = {}
    if group_name:
        group_as_obj = None
        try:
            group_as_obj = ast.literal_eval(group_name)
        except (SyntaxError, ValueError):
            group_as_obj = None
        if isinstance(group_as_obj, dict):
            data["target_group"] = group_as_obj
        else:
            grp_response = client.request("GET", endpoint_group_by_name(group_name))
            grp_data = grp_response.get("data")
            if not grp_data:
                raise ActionFailure(f"No group exists with name '{group_name}'")
            grp = get_response_data(grp_data, "group")
            data["target_group"] = {
                "source_id": grp.get("id"),
                "name": str(grp.get("name")),
            }

    ag_response = client.request("GET", endpoint_action_group_by_name(action_group))
    ag_data = ag_response.get("data")
    if not ag_data:
        raise ActionFailure(f"No action group exists with name '{action_group}'")
    ag = get_response_data(ag_data, "action group")

    data.update(
        {
            "action_group": {"id": ag.get("id")},
            "package_spec": package_spec,
            "name": action_name,
            "expire_seconds": expire_seconds,
        }
    )
    if distribute_seconds:
        data["distribute_seconds"] = distribute_seconds
    if issue_seconds:
        data["issue_seconds"] = issue_seconds

    result_data = client.request("POST", API_V2_SAVED_ACTIONS, json=data).get("data")
    if not result_data:
        raise ActionFailure("No data returned from execute action call")
    return get_response_data(result_data, "created saved action")
