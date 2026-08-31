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
from time import sleep
from typing import Any

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField, PermissiveActionOutput
from soar_sdk.exceptions import ActionFailure
from soar_sdk.params import Param, Params

from ..asset import Asset
from ..constants import (
    API_V2_QUESTIONS,
    endpoint_group_by_name,
    endpoint_question_result_data,
)
from ..tanium_client import TaniumClient, get_client
from ..utils import normalize_result_data

_WAIT_SECONDS = 5


class ListProcessesParams(Params):
    sensor: str = Param(
        description="Sensor which will list all the processes",
        default="Process Details",
    )
    group_name: str | None = Param(
        description="Computer group name of which the processes will be listed"
    )
    timeout_seconds: int = Param(
        description="The number of seconds before the question expires", default=600
    )


class ListProcessesColumnsOutput(PermissiveActionOutput):
    hash: float | None = OutputField(example_values=[3744593586])
    name: str | None = OutputField(example_values=["Process"])
    type: float | None = OutputField(example_values=[1])


class ListProcessesCellEntryOutput(PermissiveActionOutput):
    text: str | None = OutputField(example_values=["explorer.exe"])


class ListProcessesCellOutput(PermissiveActionOutput):
    text: str | None = OutputField(example_values=["explorer.exe"])
    entries: list[ListProcessesCellEntryOutput] | None = None


class ListProcessesRowsOutput(PermissiveActionOutput):
    cid: float | None = OutputField(example_values=[0])
    data: list[ListProcessesCellOutput] | None = None
    id: float | None = OutputField(example_values=[58783672])


class ListProcessesResultSetsOutput(PermissiveActionOutput):
    age: float | None = OutputField(example_values=[0])
    archived_question_id: float | None = OutputField(
        cef_types=["taniumrest question id"], example_values=[0]
    )
    cache_id: str | None = OutputField(example_values=["12418149"])
    columns: list[ListProcessesColumnsOutput] | None = None
    error_count: float | None = OutputField(example_values=[0])
    estimated_total: float | None = OutputField(example_values=[2])
    expiration: float | None = OutputField(example_values=[0])
    expire_seconds: float | None = OutputField(example_values=[0])
    filtered_row_count: float | None = OutputField(example_values=[35])
    filtered_row_count_machines: float | None = OutputField(example_values=[53])
    id: float | None = OutputField(
        cef_types=["taniumrest question id"], example_values=[58456]
    )
    issue_seconds: float | None = OutputField(example_values=[0])
    item_count: float | None = OutputField(example_values=[35])
    mr_passed: float | None = OutputField(example_values=[2])
    mr_tested: float | None = OutputField(example_values=[2])
    no_results_count: float | None = OutputField(example_values=[0])
    passed: float | None = OutputField(example_values=[2])
    question_id: float | None = OutputField(
        cef_types=["taniumrest question id"], example_values=[58456]
    )
    report_count: float | None = OutputField(example_values=[2])
    row_count: float | None = OutputField(example_values=[35])
    row_count_machines: float | None = OutputField(example_values=[53])
    rows: list[ListProcessesRowsOutput] | None = None
    saved_question_id: float | None = OutputField(example_values=[0])
    seconds_since_issued: float | None = OutputField(example_values=[0])
    select_count: float | None = OutputField(example_values=[1])
    tested: float | None = OutputField(example_values=[2])


class ListProcessesDataOutput(PermissiveActionOutput):
    max_available_age: str | None = None
    now: str | None = OutputField(example_values=["2019/07/24 11:43:42 GMT-0000"])
    result_sets: list[ListProcessesResultSetsOutput] | None = None


class ListProcessesOutput(PermissiveActionOutput):
    data: ListProcessesDataOutput | None = None


class ListProcessesSummaryOutput(ActionOutput):
    num_results: int = OutputField(example_values=[35])
    timeout_seconds: int = OutputField(example_values=[600])


def _poll_question_results(
    client: TaniumClient,
    question_id: int,
    timeout_seconds: float,
    results_percentage: int,
) -> dict[str, Any]:
    endpoint = endpoint_question_result_data(question_id)
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
        if int(percentage_returned) < int(results_percentage):
            continue
        if result_sets[0].get("columns"):
            return normalize_result_data(response)

    raise ActionFailure(
        "Error while fetching the results from the Tanium server in "
        f"'{timeout_seconds}' expire seconds. Please try increasing the timeout value"
    )


def list_processes(
    params: ListProcessesParams, soar: SOARClient, asset: Asset
) -> ListProcessesOutput:
    timeout_seconds = params.timeout_seconds
    if timeout_seconds <= 0:
        raise ActionFailure(
            "Please provide a valid non-zero non-negative integer value in the 'timeout_seconds' action parameter"
        )
    data: dict = {"expire_seconds": timeout_seconds}

    with get_client(asset) as client:
        if params.group_name:
            grp_response = client.request(
                "GET", endpoint_group_by_name(params.group_name)
            )
            grp_data = grp_response.get("data")
            if not grp_data:
                raise ActionFailure(f"No group exists with name '{params.group_name}'")
            if isinstance(grp_data, list):
                if len(grp_data) != 1:
                    raise ActionFailure(f"Expected one group, got {len(grp_data)}")
                grp = grp_data[0]
            else:
                grp = grp_data
            data["context_group"] = {"id": grp["id"]}

        data["selects"] = [{"sensor": {"name": params.sensor}}]

        post_response = client.request("POST", API_V2_QUESTIONS, json=data)
        question_id = post_response.get("data", {}).get("id")
        if not question_id:
            raise ActionFailure("Failed to obtain question ID from Tanium")

        response = _poll_question_results(
            client,
            question_id=question_id,
            timeout_seconds=timeout_seconds,
            results_percentage=(
                99 if asset.results_percentage is None else asset.results_percentage
            ),
        )
    output = ListProcessesOutput.model_validate(response)
    result_sets = output.data.result_sets if output.data else None
    num_results = result_sets[0].row_count or 0 if result_sets else 0
    soar.set_summary(
        ListProcessesSummaryOutput(
            num_results=int(num_results), timeout_seconds=timeout_seconds
        )
    )
    soar.set_message(
        f"Num results: {int(num_results)}, Timeout seconds: {timeout_seconds}"
    )
    return output
