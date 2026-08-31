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
from ..constants import API_V2_QUESTIONS, API_V2_SAVED_QUESTIONS
from ..tanium_client import get_client


class ListQuestionsParams(Params):
    list_saved_questions: bool = Param(
        description="Retrieve Saved Questions", default=True
    )


class ArchiveOwnerOutput(PermissiveActionOutput):
    id: float | None = OutputField(example_values=[1])
    name: str | None = OutputField(example_values=["administrator"])


class ListQuestionsContentSetOutput(PermissiveActionOutput):
    id: float | None = OutputField(example_values=[7])
    name: str | None = OutputField(example_values=["Detect Service"])


class ContextGroupOutput(PermissiveActionOutput):
    id: float | None = None


class ManagementRightsGroupOutput(PermissiveActionOutput):
    id: float | None = None


class MetadataOutput(PermissiveActionOutput):
    admin_flag: bool | None = None
    name: str | None = OutputField(example_values=["SQPreference_Default"])
    value: str | None = OutputField(
        example_values=[
            '{"default_grid_zoom_level":0,"default_line_zoom_level":12,"default_tab":1,"merge_flag":0,"drilldown_flag":0}'
        ]
    )


class ListQuestionsModUserOutput(PermissiveActionOutput):
    display_name: str | None = None
    domain: str | None = OutputField(cef_types=["domain"])
    id: float | None = OutputField(example_values=[1])
    name: str | None = OutputField(example_values=["administrator"])


class PackagesOutput(PermissiveActionOutput):
    id: float | None = OutputField(example_values=[1])
    name: str | None = OutputField(
        example_values=["Distribute Tanium Standard Utilities"]
    )


class QuestionOutput(PermissiveActionOutput):
    id: float | None = OutputField(
        cef_types=["taniumrest question id"], example_values=[56071]
    )


class SavedQuestionOutput(PermissiveActionOutput):
    id: float | None = OutputField(example_values=[15])


class ListQuestionsUserOutput(PermissiveActionOutput):
    deleted_flag: bool | None = None
    id: float | None = OutputField(example_values=[1])
    name: str | None = OutputField(example_values=["administrator"])


class ListQuestionsOutput(PermissiveActionOutput):
    action_tracking_flag: bool | None = None
    archive_enabled_flag: bool | None = None
    archive_owner: ArchiveOwnerOutput | None = None
    content_set: ListQuestionsContentSetOutput | None = None
    context_group: ContextGroupOutput | None = None
    expiration: str | None = OutputField(example_values=["2001-01-01T00:00:00Z"])
    expire_seconds: float | None = OutputField(example_values=[600])
    hidden_flag: bool | None = None
    id: float = OutputField(
        column_name="Question ID",
        cef_types=["taniumrest question id"],
        example_values=[26],
    )
    is_expired: bool | None = None
    issue_seconds: float | None = OutputField(example_values=[300])
    issue_seconds_never_flag: bool | None = None
    keep_seconds: float | None = OutputField(example_values=[0])
    management_rights_group: ManagementRightsGroupOutput | None = None
    metadata: list[MetadataOutput] | None = None
    mod_time: str | None = OutputField(example_values=["2019-02-11T21:22:25Z"])
    mod_user: ListQuestionsModUserOutput | None = None
    most_recent_question_id: float | None = OutputField(
        cef_types=["taniumrest question id"], example_values=[56071]
    )
    name: str | None = OutputField(
        column_name="Question Name", example_values=["Detect Managed Unix Endpoints"]
    )
    packages: list[PackagesOutput] | None = None
    public_flag: bool | None = None
    query_text: str | None = OutputField(
        column_name="Question Text",
        cef_types=["taniumrest question text"],
        example_values=[
            "Get Detect Tools Status from all machines with ( Detect Tools Status contains engine version and Detect Tools Status contains Unix )"
        ],
    )
    question: QuestionOutput | None = None
    row_count_flag: bool | None = None
    saved_question: SavedQuestionOutput | None = None
    skip_lock_flag: bool | None = None
    sort_column: float | None = OutputField(example_values=[0])
    user: ListQuestionsUserOutput | None = None


class ListQuestionsSummaryOutput(ActionOutput):
    num_questions: int | None = OutputField(example_values=[10])
    num_saved_questions: int | None = OutputField(example_values=[42])


def list_questions(
    params: ListQuestionsParams, soar: SOARClient, asset: Asset
) -> list[ListQuestionsOutput]:
    with get_client(asset) as client:
        if params.list_saved_questions:
            endpoint = API_V2_SAVED_QUESTIONS
            response = client.request("GET", endpoint)
            results = [
                ListQuestionsOutput.model_validate(q)
                for q in response.get("data", [])
                if q.get("id")
            ]
            soar.set_summary(
                ListQuestionsSummaryOutput(num_saved_questions=len(results))
            )
            soar.set_message(f"Num saved questions: {len(results)}")
        else:
            endpoint = API_V2_QUESTIONS
            response = client.request("GET", endpoint)
            seen_queries: set[str] = set()
            results = []
            for q in response.get("data", []):
                if q.get("id") and q.get("query_text") not in seen_queries:
                    seen_queries.add(q.get("query_text"))
                    results.append(ListQuestionsOutput.model_validate(q))
            soar.set_summary(ListQuestionsSummaryOutput(num_questions=len(results)))
            soar.set_message(f"Num questions: {len(results)}")

    return results
