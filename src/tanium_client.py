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

import json
from time import sleep
from typing import Any

import httpx

from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger
import contextlib

logger = getLogger()

# Tanium API endpoints
SESSION_URL = "/api/v2/session/login"
SAVED_QUESTIONS_URL = "/api/v2/saved_questions"
QUESTIONS_URL = "/api/v2/questions"
QUESTION_RESULTS_URL = "/api/v2/result_data/question/{question_id}"
PARSE_QUESTION_URL = "/api/v2/parse_question"
EXECUTE_ACTION_URL = "/api/v2/saved_actions"
ACTION_GROUP_URL = "/api/v2/action_groups/by-name/{action_group}"
COMPUTER_GROUPS_URL = "/api/v2/computer_groups"
GROUP_BY_NAME_URL = "/api/v2/groups/by-name/{group_name}"
CREATE_MANUAL_GROUP_URL = COMPUTER_GROUPS_URL
DELETE_MANUAL_GROUP_URL = "/api/v2/computer_groups/{group_id}"
PACKAGE_BY_NAME_URL = "/api/v2/packages/by-name/{package}"
SAVED_QUESTION_BY_NAME_URL = "/api/v2/saved_questions/by-name/{saved_question}"
SENSOR_BY_NAME_URL = "/api/v2/sensors/by-name/{sensor_name}"
SAVED_QUESTION_RESULT_URL = "/api/v2/result_data/saved_question/{saved_question_id}"
INTEGRATION_HEADER = "x-tanium-integration"

WAIT_SECONDS = 5
DEFAULT_TIMEOUT = 30
RESULTS_UNAVAILABLE = frozenset(
    [
        "[current results unavailable]",
        "[current result unavailable]",
        "[results currently unavailable]",
    ]
)
PARAMETERS_WITHOUT_INPUT = frozenset(
    ["com.tanium.components.parameters::SeparatorParameter"]
)


class TaniumClient:
    """Thin HTTP client for the Tanium REST API."""

    def __init__(self, asset: Any) -> None:
        base_url = asset.base_url.strip("/\\")
        self._base_url = base_url
        self._verify = bool(asset.verify_server_cert)
        self._integration_header_value = (asset.integration_header_value or "").strip()
        self._api_token: str | None = asset.api_token
        self._username: str | None = asset.username
        self._password: str | None = asset.password
        self._asset = asset

        if not self._api_token and not (self._username and self._password):
            raise ActionFailure(
                "Please provide either an API token, or username and password credentials"
            )

        self._session_id: str = self._api_token or asset.auth_state.get(
            "session_id", ""
        )

    def _headers(self, include_session: bool = True) -> dict[str, str]:
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self._integration_header_value:
            headers[INTEGRATION_HEADER] = self._integration_header_value
        if include_session and self._session_id:
            headers["session"] = str(self._session_id)
        return headers

    def _request(self, method: str, endpoint: str, **kwargs: Any) -> dict[str, Any]:
        url = f"{self._base_url}{endpoint}"
        kwargs.setdefault("timeout", DEFAULT_TIMEOUT)
        kwargs["headers"] = self._headers()

        try:
            with httpx.Client(verify=self._verify) as client:
                response = client.request(method, url, **kwargs)
        except httpx.ConnectError as e:
            raise ActionFailure(
                f"Could not connect to '{self._base_url}'. "
                "Check that the Base URL is correct (include https:// or http://) "
                "and that the Tanium server is reachable from SOAR. "
                f"Detail: {e}"
            ) from e
        except httpx.TimeoutException as e:
            raise ActionFailure(
                f"Connection to '{self._base_url}' timed out. Detail: {e}"
            ) from e

        if response.status_code in (401, 403) and (self._username and self._password):
            logger.debug(
                f"Request returned {response.status_code}, re-authenticating with credentials"
            )
            self._authenticate()
            kwargs["headers"] = self._headers()
            try:
                with httpx.Client(verify=self._verify) as client:
                    response = client.request(method, url, **kwargs)
            except httpx.ConnectError as e:
                raise ActionFailure(
                    f"Could not connect to '{self._base_url}'. "
                    "Check that the Base URL is correct (include https:// or http://) "
                    "and that the Tanium server is reachable from SOAR. "
                    f"Detail: {e}"
                ) from e

        self._raise_for_status(response)
        return response.json()

    def _raise_for_status(self, response: httpx.Response) -> None:
        if response.status_code < 400:
            return
        try:
            body = response.json()
            msg = body.get("text") or response.text
        except Exception:
            msg = response.text or "Empty response"
        error = f"Status {response.status_code}: {msg}"
        if response.status_code == 404:
            error += (
                "\nThis error usually means the account does not have sufficient "
                "permissions. See Tanium documentation for more information."
            )
        raise ActionFailure(error)

    def _authenticate(self) -> None:
        url = f"{self._base_url}{SESSION_URL}"
        payload = {"username": self._username, "password": self._password}
        headers = {"Content-Type": "application/json"}
        if self._integration_header_value:
            headers[INTEGRATION_HEADER] = self._integration_header_value

        try:
            with httpx.Client(verify=self._verify) as client:
                response = client.post(
                    url, json=payload, headers=headers, timeout=DEFAULT_TIMEOUT
                )
        except httpx.ConnectError as e:
            raise ActionFailure(
                f"Could not connect to '{self._base_url}'. "
                "Check that the Base URL is correct (include https:// or http://) "
                "and that the Tanium server is reachable from SOAR. "
                f"Detail: {e}"
            ) from e

        self._raise_for_status(response)
        session_id = response.json().get("data", {}).get("session")
        if not session_id:
            raise ActionFailure("Failed to obtain session token from Tanium")

        self._session_id = session_id
        self._asset.auth_state["session_id"] = session_id

    def ensure_authenticated(self) -> None:
        """Authenticate if no session token is available."""
        if not self._session_id:
            self._authenticate()

    def get(self, endpoint: str, **kwargs: Any) -> dict[str, Any]:
        return self._request("GET", endpoint, **kwargs)

    def post(self, endpoint: str, **kwargs: Any) -> dict[str, Any]:
        return self._request("POST", endpoint, **kwargs)

    def delete(self, endpoint: str, **kwargs: Any) -> dict[str, Any]:
        return self._request("DELETE", endpoint, **kwargs)

    def get_single(self, response_data: Any, resource_name: str) -> dict[str, Any]:
        """Extract exactly one record from a response data field."""
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

    def poll_question_results(
        self,
        question_id: int,
        timeout_seconds: float,
        results_percentage: float,
        wait_for_results_processing: bool = False,
        return_when_n_results_available: int | None = None,
        wait_for_n_results_available: int | None = None,
    ) -> dict[str, Any]:
        """Poll Tanium until question results meet the completion threshold."""
        endpoint = QUESTION_RESULTS_URL.format(question_id=question_id)
        max_range = int(timeout_seconds / WAIT_SECONDS) + (
            1 if timeout_seconds % WAIT_SECONDS == 0 else 2
        )

        for i in range(1, max_range):
            if timeout_seconds > WAIT_SECONDS:
                wait = (
                    timeout_seconds - (i - 1) * WAIT_SECONDS - 1
                    if i == max_range - 1
                    else WAIT_SECONDS
                )
            else:
                wait = timeout_seconds - 1
            sleep(wait)

            response = self.get(endpoint)
            data = response.get("data", {})
            result_sets = data.get("result_sets", [])
            if not result_sets:
                continue

            mr_tested = result_sets[0].get("mr_tested")
            estimated_total = result_sets[0].get("estimated_total")
            if not (mr_tested and estimated_total):
                continue

            percentage_returned = float(mr_tested) / float(estimated_total) * 100
            num_complete, num_incomplete = self._count_results(data)

            if wait_for_results_processing:
                num_results = num_complete
            else:
                num_results = num_complete + num_incomplete

            if wait_for_results_processing and num_incomplete > 0:
                continue
            if (
                return_when_n_results_available
                and num_results >= return_when_n_results_available
            ):
                return response
            if (
                wait_for_n_results_available
                and num_complete < wait_for_n_results_available
            ):
                continue
            if int(percentage_returned) < int(results_percentage):
                continue

            if result_sets[0].get("columns"):
                rows = result_sets[0].get("rows", [])
                for j, row in enumerate(rows):
                    formatted = [item[0] for item in row.get("data", [])]
                    response["data"]["result_sets"][0]["rows"][j]["data"] = formatted
                return response

        raise ActionFailure(
            f"Timed out waiting for question results after {timeout_seconds}s. "
            "Try increasing the timeout value."
        )

    def _count_results(self, data: dict[str, Any]) -> tuple[int, int]:
        """Return (num_complete, num_incomplete) for a question result set."""
        num_complete = 0
        num_incomplete = 0
        rows = data.get("result_sets", [{}])[0].get("rows", [])
        for row in rows:
            incomplete = False
            for row_data_element in row.get("data", []):
                for entry in row_data_element:
                    if entry.get("text", "") in RESULTS_UNAVAILABLE:
                        incomplete = True
                        num_incomplete += 1
                        break
                if incomplete:
                    break
            else:
                num_complete += 1
        return num_complete, num_incomplete

    def poll_saved_question_results(
        self,
        saved_question_id: int,
        timeout_seconds: float,
        results_percentage: float,
        wait_for_results_processing: bool = False,
        return_when_n_results_available: int | None = None,
        wait_for_n_results_available: int | None = None,
    ) -> dict[str, Any]:
        """Poll Tanium until saved question results meet the completion threshold."""
        endpoint = SAVED_QUESTION_RESULT_URL.format(saved_question_id=saved_question_id)
        max_range = int(timeout_seconds / WAIT_SECONDS) + (
            1 if timeout_seconds % WAIT_SECONDS == 0 else 2
        )

        for i in range(1, max_range):
            if timeout_seconds > WAIT_SECONDS:
                wait = (
                    timeout_seconds - (i - 1) * WAIT_SECONDS - 1
                    if i == max_range - 1
                    else WAIT_SECONDS
                )
            else:
                wait = timeout_seconds - 1
            sleep(wait)

            response = self.get(endpoint)
            data = response.get("data", {})
            result_sets = data.get("result_sets", [])
            if not result_sets:
                continue

            mr_tested = result_sets[0].get("mr_tested")
            estimated_total = result_sets[0].get("estimated_total")
            if not (mr_tested and estimated_total):
                continue

            percentage_returned = float(mr_tested) / float(estimated_total) * 100
            num_complete, num_incomplete = self._count_results(data)

            if wait_for_results_processing:
                num_results = num_complete
            else:
                num_results = num_complete + num_incomplete

            if wait_for_results_processing and num_incomplete > 0:
                continue
            if (
                return_when_n_results_available
                and num_results >= return_when_n_results_available
            ):
                return response
            if (
                wait_for_n_results_available
                and num_complete < wait_for_n_results_available
            ):
                continue
            if int(percentage_returned) < int(results_percentage):
                continue

            if result_sets[0].get("columns"):
                rows = result_sets[0].get("rows", [])
                for j, row in enumerate(rows):
                    formatted = [item[0] for item in row.get("data", [])]
                    response["data"]["result_sets"][0]["rows"][j]["data"] = formatted
                return response

        raise ActionFailure(
            f"Timed out waiting for saved question results after {timeout_seconds}s. "
            "Try increasing the timeout value."
        )

    def parse_and_validate_question(
        self, query_text: str, group_context: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Parse query text via Tanium, validate it, and return the question data dict ready to POST to /questions."""
        data: dict[str, Any] = {}
        if group_context:
            data.update(group_context)

        response = self.post(PARSE_QUESTION_URL, json={"text": query_text})
        parsed = response.get("data", [])

        if len(parsed) != 1:
            raise ActionFailure(
                "Please provide a valid parsed question accepted by Tanium server"
            )

        resp_text = (
            parsed[0].get("question_text", "").lower().replace('"', "").replace("'", "")
        )
        query_text_normalized = query_text.lower().replace('"', "").replace("'", "")

        if resp_text != query_text_normalized:
            raise ActionFailure(
                "Please provide a valid parsed question accepted by Tanium server"
            )

        if parsed[0].get("parameter_values"):
            question_data = self._parameterize_query(parsed[0])
        else:
            question_data = dict(parsed[0])

        data.update(question_data)
        return data

    def _parameterize_query(self, query: dict[str, Any]) -> dict[str, Any]:
        selects = query["selects"]
        param_list = query["parameter_values"]
        self._param_idx = 0

        question_data: dict[str, Any] = {
            "selects": selects,
            "question_text": query["question_text"],
        }
        if "group" in query:
            question_data["group"] = query["group"]

        question_data = self._load_full_sensors_to_obj(question_data, param_list)

        if self._param_idx and self._param_idx != len(param_list):
            raise ActionFailure(
                "Please provide the exact number of parameters expected by the sensor"
            )

        return question_data

    def _load_full_sensors_to_obj(self, obj: Any, param_list: list[Any]) -> Any:
        if isinstance(obj, list):
            return [self._load_full_sensors_to_obj(item, param_list) for item in obj]
        if isinstance(obj, dict):
            if "sensor" in obj:
                obj["sensor"] = self._create_sensor_dict(obj["sensor"], param_list)
                return obj
            return {
                k: self._load_full_sensors_to_obj(v, param_list) for k, v in obj.items()
            }
        return obj

    def _create_sensor_dict(
        self, sensor: dict[str, Any], param_list: list[Any]
    ) -> dict[str, Any]:
        sensor_name = sensor["name"]
        response = self.get(SENSOR_BY_NAME_URL.format(sensor_name=sensor_name))
        response_data = response.get("data")
        if not response_data:
            raise ActionFailure(f"No sensor exists with name {sensor_name}")

        resp_data = self.get_single(response_data, "sensor")
        raw_pd = resp_data.get("parameter_definition", "")
        if not raw_pd:
            return sensor

        try:
            parameter_definition = json.loads(raw_pd)
        except Exception as e:
            raise ActionFailure(
                f"Error parsing sensor parameter_definition: {e}"
            ) from e

        if not parameter_definition:
            return sensor

        parameters = []
        for pd_param in parameter_definition["parameters"]:
            key = pd_param["key"]
            if self._param_idx >= len(param_list):
                raise ActionFailure(
                    "Not enough parameter values provided for the sensor"
                )
            parameters.append(
                {"key": f"||{key}||", "value": param_list[self._param_idx]}
            )
            self._param_idx += 1

        return {
            "source_hash": sensor["hash"],
            "name": sensor_name,
            "parameters": parameters,
        }

    def execute_action_support(
        self,
        action_name: str,
        action_group: str,
        package_name: str,
        expire_seconds: int,
        package_parameters: str | None = None,
        group_name: str | None = None,
        distribute_seconds: int | None = None,
        issue_seconds: int | None = None,
    ) -> dict[str, Any]:
        """Shared logic for terminate_process and execute_action."""
        import ast

        # Fetch package
        pkg_response = self.get(PACKAGE_BY_NAME_URL.format(package=package_name))
        pkg_data = pkg_response.get("data")
        if not pkg_data:
            raise ActionFailure(f"No package exists with name '{package_name}'")
        pkg = self.get_single(pkg_data, "package")
        package_id = pkg.get("id")

        # Parse parameter_definition
        raw_pd = (
            pkg_response.get("data", {}).get("parameter_definition")
            if isinstance(pkg_data, dict)
            else pkg.get("parameter_definition")
        )
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

        # Validate and build package parameters
        package_param: list[dict[str, Any]] = []
        if parameter_definition and parameter_definition.get("parameters"):
            count_required = sum(
                1
                for p in parameter_definition["parameters"]
                if p.get("parameterType") not in PARAMETERS_WITHOUT_INPUT
            )
            if count_required > 0:
                if package_parameters is None:
                    raise ActionFailure(
                        "Please provide the required package parameter in the following format: "
                        '{"<key_1>": "<value_1>", "<key_2>": "<value_2>"}'
                    )
                try:
                    parsed_params: dict[str, str] = json.loads(package_parameters)
                except Exception as e:
                    raise ActionFailure(
                        f"Error parsing 'package_parameters': {e}"
                    ) from e

                if len(parsed_params) != count_required:
                    raise ActionFailure(
                        "Please provide all the required package parameters in 'package_parameters'"
                    )

                valid_keys = {p["key"] for p in parameter_definition["parameters"]}
                invalid = [k for k in parsed_params if k not in valid_keys]
                if invalid:
                    raise ActionFailure(
                        f"The following key(s) are incorrect: {', '.join(invalid)}. Please provide correct key(s)"
                    )

                package_param = [
                    {"key": k, "value": v} for k, v in parsed_params.items()
                ]

        package_spec: dict[str, Any] = {"source_id": package_id}
        if package_param:
            package_spec["parameters"] = package_param

        # Resolve target group
        data: dict[str, Any] = {}
        if group_name:
            group_as_obj = None
            with contextlib.suppress(SyntaxError, ValueError):
                group_as_obj = ast.literal_eval(group_name)

            if group_as_obj:
                data["target_group"] = group_as_obj
            else:
                grp_response = self.get(GROUP_BY_NAME_URL.format(group_name=group_name))
                grp_data = grp_response.get("data")
                if not grp_data:
                    raise ActionFailure(f"No group exists with name '{group_name}'")
                grp = self.get_single(grp_data, "group")
                data["target_group"] = {
                    "source_id": grp.get("id"),
                    "name": str(grp.get("name")),
                }

        # Resolve action group
        ag_response = self.get(ACTION_GROUP_URL.format(action_group=action_group))
        ag_data = ag_response.get("data")
        if not ag_data:
            raise ActionFailure(f"No action group exists with name '{action_group}'")
        ag = self.get_single(ag_data, "action group")

        data["action_group"] = {"id": ag.get("id")}
        data["package_spec"] = package_spec
        data["name"] = action_name
        data["expire_seconds"] = expire_seconds

        if distribute_seconds:
            data["distribute_seconds"] = distribute_seconds
        if issue_seconds:
            data["issue_seconds"] = issue_seconds

        response = self.post(EXECUTE_ACTION_URL, json=data)
        result = response.get("data")
        if not result:
            raise ActionFailure("No data returned from execute action call")
        return result
