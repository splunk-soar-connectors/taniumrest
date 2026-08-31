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
from soar_sdk.params import Param, Params

from ..asset import Asset
from ..constants import API_V2_PARSE_QUESTION
from ..tanium_client import get_client


class ParseQuestionParams(Params):
    query_text: str = Param(
        description="Query text to parse",
        primary=True,
        cef_types=["taniumrest question text"],
    )


class FilterOutput(PermissiveActionOutput):
    all_values_flag: bool | None = None
    delimiter: str | None = None
    delimiter_index: float | None = None
    ignore_case_flag: bool | None = None
    max_age_seconds: float | None = None
    not_flag: bool | None = None
    operator: str | None = OutputField(example_values=["RegexMatch"])
    substring_flag: bool | None = None
    substring_length: float | None = None
    substring_start: float | None = None
    value: str | None = None
    value_type: str | None = OutputField(example_values=["String"])


class SensorOutput(PermissiveActionOutput):
    delimiter: str | None = OutputField(example_values=[","])
    hash: float | None = OutputField(example_values=[3867657808])
    id: float | None = OutputField(example_values=[350])
    max_age_seconds: float | None = OutputField(example_values=[86400])
    name: str | None = OutputField(example_values=["Child Processes"])
    parameter_definition: str | None = None
    value_type: str | None = OutputField(example_values=["String"])


class SelectsOutput(PermissiveActionOutput):
    filter: FilterOutput | None = None
    sensor: SensorOutput | None = None


class SensorReferencesOutput(PermissiveActionOutput):
    name: str | None = OutputField(example_values=["Child Processes"])
    real_ms_avg: float | None = OutputField(example_values=[0])
    start_char: float | None = OutputField(example_values=[4])


class ParseQuestionOutput(PermissiveActionOutput):
    expire_seconds: float | None = OutputField(example_values=[600])
    force_computer_id_flag: float | None = None
    from_canonical_text: float | None = OutputField(example_values=[0])
    group: str | None = OutputField(
        cef_types=["taniumrest group definition"],
        example_values=["{ group id object }"],
    )
    question_text: str | None = OutputField(
        column_name="PARSED QUESTION",
        cef_types=["taniumrest question text"],
        example_values=["Get Child Processes from all machines"],
    )
    score: float | None = OutputField(example_values=[7082])
    selects: list[SelectsOutput] | None = None
    sensor_references: list[SensorReferencesOutput] | None = None
    skip_lock_flag: float | None = None


class ParseQuestionSummaryOutput(ActionOutput):
    number_of_parsed_questions: int = OutputField(example_values=[5])


def parse_question(
    params: ParseQuestionParams, soar: SOARClient, asset: Asset
) -> list[ParseQuestionOutput]:
    with get_client(asset) as client:
        response = client.request(
            "POST",
            API_V2_PARSE_QUESTION,
            json={"text": params.query_text},
        )
    results = [
        ParseQuestionOutput.model_validate(item) for item in response.get("data", [])
    ]
    soar.set_summary(
        ParseQuestionSummaryOutput(number_of_parsed_questions=len(results))
    )
    soar.set_message(f"Number of parsed questions: {len(results)}")
    return results
