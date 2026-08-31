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
from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField, PermissiveActionOutput
from soar_sdk.exceptions import ActionFailure
from soar_sdk.params import Param, Params

from ..asset import Asset
from ..constants import endpoint_question_result_data
from ..tanium_client import get_client


class GetQuestionResultsParams(Params):
    question_id: int = Param(
        description="The ID of the question",
        primary=True,
        cef_types=["taniumrest question id"],
    )


class GetQuestionResultsColumnsOutput(PermissiveActionOutput):
    hash: float | None = OutputField(example_values=[3112892791])
    name: str | None = OutputField(example_values=["DNS Server"])
    type: float | None = OutputField(example_values=[5])


class GetQuestionResultsCellEntryOutput(PermissiveActionOutput):
    text: str | None = OutputField(example_values=["192.168.1.1"])


class GetQuestionResultsRowsOutput(PermissiveActionOutput):
    cid: float | None = OutputField(example_values=[0])
    data: list[list[GetQuestionResultsCellEntryOutput]] | None = None
    id: float | None = OutputField(example_values=[1306085003])


class GetQuestionResultsResultSetsOutput(PermissiveActionOutput):
    age: float | None = OutputField(example_values=[0])
    archived_question_id: float | None = OutputField(example_values=[0])
    cache_id: str | None = OutputField(example_values=["2668614289"])
    columns: list[GetQuestionResultsColumnsOutput] | None = None
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
    rows: list[GetQuestionResultsRowsOutput] | None = None
    saved_question_id: float | None = OutputField(example_values=[0])
    seconds_since_issued: float | None = OutputField(example_values=[0])
    select_count: float | None = OutputField(example_values=[1])
    tested: float | None = OutputField(example_values=[1])


class GetQuestionResultsDataOutput(PermissiveActionOutput):
    max_available_age: str | None = None
    now: str | None = OutputField(example_values=["2019/07/24 07:53:06 GMT-0000"])
    result_sets: list[GetQuestionResultsResultSetsOutput] | None = None


class GetQuestionResultsOutput(PermissiveActionOutput):
    data: GetQuestionResultsDataOutput | None = None


class GetQuestionResultsSummaryOutput(ActionOutput):
    number_of_rows: int = OutputField(example_values=[1])


def get_question_results(
    params: GetQuestionResultsParams, soar: SOARClient, asset: Asset
) -> GetQuestionResultsOutput:
    if params.question_id < 0:
        raise ActionFailure(
            "Please provide a valid non-negative integer value in the 'question_id' action parameter"
        )

    try:
        with get_client(asset) as client:
            response = client.request(
                "GET", endpoint_question_result_data(params.question_id)
            )
    except ActionFailure as e:
        raise ActionFailure(f"Getting question results failed. {e}") from e

    output = GetQuestionResultsOutput.model_validate(response)
    result_sets = response.get("data", {}).get("result_sets") or []
    row_count = (result_sets[0].get("row_count") or 0) if result_sets else 0
    soar.set_summary(GetQuestionResultsSummaryOutput(number_of_rows=int(row_count)))
    soar.set_message(f"Number of rows: {int(row_count)}")
    return output
