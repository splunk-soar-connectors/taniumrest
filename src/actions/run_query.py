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
from time import sleep
from typing import Any

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField, PermissiveActionOutput
from soar_sdk.exceptions import ActionFailure
from soar_sdk.params import Param, Params

from ..asset import Asset
from ..constants import (
    API_V2_PARSE_QUESTION,
    API_V2_QUESTIONS,
    endpoint_group_by_name,
    endpoint_question_result_data,
    endpoint_saved_question_by_name,
    endpoint_saved_question_result_data,
    endpoint_sensor_by_name,
)
from ..tanium_client import TaniumClient, get_client
from ..utils import get_response_data, normalize_result_data

_WAIT_SECONDS = 5


class RunQueryParams(Params):
    query_text: str = Param(
        description="Query to run (in Tanium Question Syntax)",
        primary=True,
        cef_types=["taniumrest question text"],
    )
    group_name: str | None = Param(
        description="The Tanium Computer Group name on which the query will be executed (manual query only)"
    )
    is_saved_question: bool | None = Param(
        description="Check this box if the query text parameter refers to a 'Saved Question' on your Tanium",
        default=False,
    )
    timeout_seconds: int = Param(
        description="The number of seconds before the question expires (manual query only)",
        default=600,
    )
    return_when_n_results_available: int | None = Param(
        description="Return results as soon as 'n' answers are available"
    )
    wait_for_n_results_available: int | None = Param(
        description="Wait until 'n' results are present, even if hit the percent complete threshold"
    )


class RunQueryColumnsOutput(PermissiveActionOutput):
    hash: float | None = OutputField(example_values=[3112892791])
    name: str | None = OutputField(example_values=["DNS Server"])
    type: float | None = OutputField(example_values=[5])


class RunQueryCellEntryOutput(PermissiveActionOutput):
    text: str | None = OutputField(example_values=["192.168.1.1"])


class RunQueryCellOutput(PermissiveActionOutput):
    text: str | None = OutputField(example_values=["192.168.1.1"])
    entries: list[RunQueryCellEntryOutput] | None = None


class RunQueryRowsOutput(PermissiveActionOutput):
    cid: float | None = OutputField(example_values=[0])
    data: list[RunQueryCellOutput] | None = None
    id: float | None = OutputField(example_values=[1306085003])


class RunQueryResultSetsOutput(PermissiveActionOutput):
    age: float | None = OutputField(example_values=[0])
    archived_question_id: float | None = OutputField(example_values=[0])
    cache_id: str | None = OutputField(example_values=["2668614289"])
    columns: list[RunQueryColumnsOutput] | None = None
    error_count: float | None = OutputField(example_values=[0])
    estimated_total: float | None = OutputField(example_values=[2])
    expiration: float | None = OutputField(example_values=[0])
    expire_seconds: float | None = OutputField(example_values=[0])
    filtered_row_count: float | None = OutputField(example_values=[1])
    filtered_row_count_machines: float | None = OutputField(example_values=[1])
    id: float | None = OutputField(
        cef_types=["taniumrest question id"], example_values=[58377]
    )
    issue_seconds: float | None = OutputField(example_values=[0])
    item_count: float | None = OutputField(example_values=[1])
    mr_passed: float | None = OutputField(example_values=[1])
    mr_tested: float | None = OutputField(example_values=[2])
    no_results_count: float | None = OutputField(example_values=[0])
    passed: float | None = OutputField(example_values=[1])
    question_id: float | None = OutputField(
        cef_types=["taniumrest question id"], example_values=[58377]
    )
    report_count: float | None = OutputField(example_values=[2])
    row_count: float | None = OutputField(example_values=[1])
    row_count_machines: float | None = OutputField(example_values=[1])
    rows: list[RunQueryRowsOutput] | None = None
    saved_question_id: float | None = OutputField(example_values=[0])
    seconds_since_issued: float | None = OutputField(example_values=[0])
    select_count: float | None = OutputField(example_values=[1])
    tested: float | None = OutputField(example_values=[1])


class RunQueryDataOutput(PermissiveActionOutput):
    max_available_age: str | None = None
    now: str | None = OutputField(example_values=["2019/07/24 07:53:06 GMT-0000"])
    result_sets: list[RunQueryResultSetsOutput] | None = None


class RunQueryOutput(PermissiveActionOutput):
    data: RunQueryDataOutput | None = None


class RunQuerySummaryOutput(ActionOutput):
    timeout_seconds: int = OutputField(example_values=[600])
    number_of_rows: int = OutputField(example_values=[35])


def _count_rows(data: dict[str, Any]) -> int:
    rows = data.get("result_sets", [{}])[0].get("rows", [])
    return len(rows)


def _poll_results(
    client: TaniumClient,
    endpoint: str,
    timeout_seconds: float,
    results_percentage: int,
    return_when_n_results_available: int | None = None,
    wait_for_n_results_available: int | None = None,
) -> dict[str, Any]:
    max_range = int(timeout_seconds / _WAIT_SECONDS) + (
        1 if timeout_seconds % _WAIT_SECONDS == 0 else 2
    )
    for i in range(1, max_range):
        wait = (
            timeout_seconds - (i - 1) * _WAIT_SECONDS - 1
            if (timeout_seconds > _WAIT_SECONDS and i == max_range - 1)
            else min(_WAIT_SECONDS, timeout_seconds - 1)
        )
        sleep(wait)

        response = client.request("GET", endpoint)
        data = response.get("data", {})
        result_sets = data.get("result_sets", [])
        if not result_sets:
            continue

        mr_tested = result_sets[0].get("mr_tested")
        estimated_total = result_sets[0].get("estimated_total")
        if not (mr_tested and estimated_total):
            continue

        percentage_returned = float(mr_tested) / float(estimated_total) * 100
        num_results = _count_rows(data)

        if (
            return_when_n_results_available
            and num_results >= return_when_n_results_available
        ):
            return normalize_result_data(response)
        if wait_for_n_results_available and num_results < wait_for_n_results_available:
            continue
        if int(percentage_returned) < int(results_percentage):
            continue
        if result_sets[0].get("columns"):
            return normalize_result_data(response)

    raise ActionFailure(
        "Error while fetching the results from the Tanium server in "
        f"'{timeout_seconds}' expire seconds. Please try increasing the timeout value"
    )


def _create_sensor_dict(
    client: TaniumClient,
    sensor: dict[str, Any],
    param_list: list[Any],
    param_idx: list[int],
) -> dict[str, Any]:
    sensor_name = sensor["name"]
    response = client.request("GET", endpoint_sensor_by_name(str(sensor_name)))
    response_data = response.get("data")
    if not response_data:
        raise ActionFailure(f"No sensor exists with name {sensor_name}")

    raw_pd = get_response_data(response_data, "sensor").get("parameter_definition", "")
    if not raw_pd:
        return sensor

    try:
        parameter_definition = json.loads(raw_pd)
    except Exception as e:
        raise ActionFailure(f"Error parsing sensor parameter_definition: {e}") from e

    if not parameter_definition:
        return sensor

    parameters = []
    for pd_param in parameter_definition["parameters"]:
        if param_idx[0] >= len(param_list):
            raise ActionFailure("Not enough parameter values provided for the sensor")
        parameters.append(
            {"key": f"||{pd_param['key']}||", "value": param_list[param_idx[0]]}
        )
        param_idx[0] += 1

    return {
        "source_hash": sensor["hash"],
        "name": sensor_name,
        "parameters": parameters,
    }


def _load_full_sensors_to_obj(
    client: TaniumClient, obj: Any, param_list: list[Any], param_idx: list[int]
) -> Any:
    if isinstance(obj, list):
        return [
            _load_full_sensors_to_obj(client, item, param_list, param_idx)
            for item in obj
        ]
    if isinstance(obj, dict):
        if "sensor" in obj:
            obj["sensor"] = _create_sensor_dict(
                client, obj["sensor"], param_list, param_idx
            )
            return obj
        return {
            k: _load_full_sensors_to_obj(client, v, param_list, param_idx)
            for k, v in obj.items()
        }
    return obj


def _parameterize_query(client: TaniumClient, query: dict[str, Any]) -> dict[str, Any]:
    param_idx = [0]
    question_data: dict[str, Any] = {
        "selects": query["selects"],
        "question_text": query["question_text"],
    }
    if "group" in query:
        question_data["group"] = query["group"]

    question_data = _load_full_sensors_to_obj(
        client, question_data, query["parameter_values"], param_idx
    )

    if param_idx[0] and param_idx[0] != len(query["parameter_values"]):
        raise ActionFailure(
            "Please provide the exact number of parameters expected by the sensor"
        )
    return question_data


def _parse_and_validate_question(
    client: TaniumClient, query_text: str, group_context: dict[str, Any] | None = None
) -> dict[str, Any]:
    data: dict[str, Any] = dict(group_context) if group_context else {}

    response = client.request("POST", API_V2_PARSE_QUESTION, json={"text": query_text})
    parsed = response.get("data", [])

    if len(parsed) != 1:
        raise ActionFailure(
            "Please provide a valid parsed question accepted by Tanium server"
        )

    resp_text = (
        parsed[0].get("question_text", "").lower().replace('"', "").replace("'", "")
    )
    if resp_text != query_text.lower().replace('"', "").replace("'", ""):
        raise ActionFailure(
            "Please provide a valid parsed question accepted by Tanium server"
        )

    question_data = (
        _parameterize_query(client, parsed[0])
        if parsed[0].get("parameter_values")
        else dict(parsed[0])
    )
    data.update(question_data)
    return data


def run_query(params: RunQueryParams, soar: SOARClient, asset: Asset) -> RunQueryOutput:
    results_percentage = (
        99 if asset.results_percentage is None else asset.results_percentage
    )
    timeout_seconds = params.timeout_seconds
    return_when_n = params.return_when_n_results_available
    wait_for_n = params.wait_for_n_results_available

    if timeout_seconds <= 0:
        raise ActionFailure(
            "Please provide a valid non-zero non-negative integer value in the 'timeout_seconds' action parameter"
        )
    if return_when_n is not None and return_when_n < 0:
        raise ActionFailure(
            "Please provide a valid non-negative integer value in the 'return_when_n_results_available' action parameter"
        )
    if wait_for_n is not None and wait_for_n < 0:
        raise ActionFailure(
            "Please provide a valid non-negative integer value in the 'wait_for_n_results_available' action parameter"
        )

    if return_when_n and wait_for_n and return_when_n < wait_for_n:
        raise ActionFailure(
            "Please provide 'return_when_n_results_available' greater than or equal to 'wait_for_n_results_available'"
        )

    with get_client(asset) as client:
        if params.is_saved_question:
            sq_response = client.request(
                "GET",
                endpoint_saved_question_by_name(str(params.query_text)),
            )
            sq_data = sq_response.get("data")
            if not sq_data:
                raise ActionFailure(
                    f"No saved question exists with name '{params.query_text}'"
                )
            sq = get_response_data(sq_data, "saved question")
            response = _poll_results(
                client,
                endpoint_saved_question_result_data(sq["id"]),
                timeout_seconds,
                results_percentage,
                return_when_n_results_available=return_when_n,
                wait_for_n_results_available=wait_for_n,
            )
        else:
            group_context: dict | None = None
            if params.group_name:
                grp_response = client.request(
                    "GET",
                    endpoint_group_by_name(str(params.group_name)),
                )
                grp_data = grp_response.get("data")
                if not grp_data:
                    raise ActionFailure(
                        f"No group exists with name '{params.group_name}'"
                    )
                grp = get_response_data(grp_data, "group")
                group_context = {"context_group": {"id": grp["id"]}}

            question_data = _parse_and_validate_question(
                client, params.query_text, group_context
            )
            question_data["expire_seconds"] = int(timeout_seconds)

            post_response = client.request("POST", API_V2_QUESTIONS, json=question_data)
            question_id = post_response.get("data", {}).get("id")
            if not question_id:
                raise ActionFailure("Failed to obtain question ID from Tanium")

            response = _poll_results(
                client,
                endpoint_question_result_data(question_id),
                timeout_seconds,
                results_percentage,
                return_when_n_results_available=return_when_n,
                wait_for_n_results_available=wait_for_n,
            )

    output = RunQueryOutput.model_validate(response)
    result_sets = output.data.result_sets if output.data else None
    number_of_rows = result_sets[0].row_count or 0 if result_sets else 0
    soar.set_summary(
        RunQuerySummaryOutput(
            timeout_seconds=timeout_seconds, number_of_rows=int(number_of_rows)
        )
    )
    soar.set_message(
        f"Timeout seconds: {timeout_seconds}, Number of rows: {int(number_of_rows)}"
    )
    return output
