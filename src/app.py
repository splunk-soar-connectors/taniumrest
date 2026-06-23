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
from soar_sdk.app import App
from soar_sdk.params import Param, Params, MakeRequestParams
from soar_sdk.action_results import ActionOutput, OutputField, MakeRequestOutput
from soar_sdk.asset import BaseAsset, AssetField
from soar_sdk.logging import getLogger

from .tanium_client import TaniumClient
from .views import (
    execute_action_view,
    get_question_results_view,
    list_processes_view,
    parse_question_view,
    run_query_view,
    terminate_process_view,
)

logger = getLogger()


class Asset(BaseAsset):
    base_url: str = AssetField(description="Base URL (e.g. https://taniumserver)")
    api_token: str | None = AssetField(description="API Token", sensitive=True)
    username: str | None = AssetField(description="Username")
    password: str | None = AssetField(description="Password", sensitive=True)
    verify_server_cert: bool | None = AssetField(
        description="Verify Server Certificate", default=False
    )
    results_percentage: float | None = AssetField(
        description="Consider question results complete at (% out of 100)", default=99.0
    )
    integration_header_value: str | None = AssetField(
        description="Optional value for the x-tanium-integration API header. Configure only when required by Tanium partner or test accounts."
    )


app = App(
    name="Tanium REST",
    app_type="endpoint",
    logo="logo_taniumrest.svg",
    logo_dark="logo_taniumrest_dark.svg",
    product_vendor="Tanium",
    product_name="Tanium REST",
    publisher="Splunk",
    appid="3b878e99-4561-434c-8fd6-3e224334af6a",
    fips_compliant=True,
    asset_cls=Asset,
)


@app.test_connectivity()
def test_connectivity(soar: SOARClient, asset: Asset):
    client = TaniumClient(asset)
    client.ensure_authenticated()
    client.get("/api/v2/saved_questions")


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


class ListProcessesColumnsOutput(ActionOutput):
    hash: float = OutputField(example_values=[3744593586])
    name: str = OutputField(example_values=["Process"])
    type: float = OutputField(example_values=[1])


class ListProcessesCellOutput(ActionOutput):
    text: str = OutputField(example_values=["explorer.exe"])


class ListProcessesRowsOutput(ActionOutput):
    cid: float = OutputField(example_values=[0])
    data: list[ListProcessesCellOutput]
    id: float = OutputField(example_values=[58783672])


class ListProcessesResultSetsOutput(ActionOutput):
    age: float = OutputField(example_values=[0])
    archived_question_id: float = OutputField(
        cef_types=["taniumrest question id"], example_values=[0]
    )
    cache_id: str = OutputField(example_values=["12418149"])
    columns: list[ListProcessesColumnsOutput]
    error_count: float = OutputField(example_values=[0])
    estimated_total: float = OutputField(example_values=[2])
    expiration: float = OutputField(example_values=[0])
    expire_seconds: float = OutputField(example_values=[0])
    filtered_row_count: float = OutputField(example_values=[35])
    filtered_row_count_machines: float = OutputField(example_values=[53])
    id: float = OutputField(
        cef_types=["taniumrest question id"], example_values=[58456]
    )
    issue_seconds: float = OutputField(example_values=[0])
    item_count: float = OutputField(example_values=[35])
    mr_passed: float = OutputField(example_values=[2])
    mr_tested: float = OutputField(example_values=[2])
    no_results_count: float = OutputField(example_values=[0])
    passed: float = OutputField(example_values=[2])
    question_id: float = OutputField(
        cef_types=["taniumrest question id"], example_values=[58456]
    )
    report_count: float = OutputField(example_values=[2])
    row_count: float = OutputField(example_values=[35])
    row_count_machines: float = OutputField(example_values=[53])
    rows: list[ListProcessesRowsOutput]
    saved_question_id: float = OutputField(example_values=[0])
    seconds_since_issued: float = OutputField(example_values=[0])
    select_count: float = OutputField(example_values=[1])
    tested: float = OutputField(example_values=[2])


class ListProcessesDataOutput(ActionOutput):
    max_available_age: str | None = None
    now: str = OutputField(example_values=["2019/07/24 11:43:42 GMT-0000"])
    result_sets: list[ListProcessesResultSetsOutput]


class ListProcessesOutput(ActionOutput):
    data: ListProcessesDataOutput


class ListProcessesSummaryOutput(ActionOutput):
    num_results: int = OutputField(example_values=[35])


@app.action(
    description="List the running processes of the devices registered on the Tanium server",
    action_type="investigate",
    verbose="This action requires specifying a sensor to be used to list processes. A standard Tanium sensor, 'Process Details' is used by default but a different sensor can be specified instead. Note that the 'Process Details' sensor may not be available on all Tanium deployments. Note that at this time this action only supports limiting the query to specified computer groups, but a generic Run Query action can be constructed to query an in individual computer's processes. As pagination is not implemented, the result(s) of the action will be the result(s) that are fetched in a single API call.",
    view_handler=app.view_handler()(list_processes_view),
)
def list_processes(
    params: ListProcessesParams, soar: SOARClient, asset: Asset
) -> ListProcessesOutput:
    client = TaniumClient(asset)
    client.ensure_authenticated()

    timeout_seconds = params.timeout_seconds
    data: dict = {"expire_seconds": int(timeout_seconds)}

    if params.group_name:
        grp_response = client.get(f"/api/v2/groups/by-name/{params.group_name}")
        grp_data = grp_response.get("data")
        if not grp_data:
            from soar_sdk.exceptions import ActionFailure

            raise ActionFailure(f"No group exists with name '{params.group_name}'")
        grp = client.get_single(grp_data, "group")
        data["context_group"] = {"id": grp["id"]}

    data["selects"] = [{"sensor": {"name": params.sensor}}]

    post_response = client.post("/api/v2/questions", json=data)
    question_id = post_response.get("data", {}).get("id")

    response = client.poll_question_results(
        question_id=question_id,
        timeout_seconds=timeout_seconds,
        results_percentage=asset.results_percentage or 99.0,
    )
    output = ListProcessesOutput.model_validate(response)
    num_results = sum(rs.row_count for rs in output.data.result_sets)
    soar.set_summary(ListProcessesSummaryOutput(num_results=int(num_results)))
    return output


class ParseQuestionParams(Params):
    query_text: str = Param(
        description="Query text to parse",
        primary=True,
        cef_types=["taniumrest question text"],
    )


class FilterOutput(ActionOutput):
    all_values_flag: bool | None = None
    delimiter: str | None = None
    delimiter_index: float | None = None
    ignore_case_flag: bool | None = None
    max_age_seconds: float | None = None
    not_flag: bool | None = None
    operator: str = OutputField(example_values=["RegexMatch"])
    substring_flag: bool | None = None
    substring_length: float | None = None
    substring_start: float | None = None
    value: str | None = None
    value_type: str = OutputField(example_values=["String"])


class SensorOutput(ActionOutput):
    delimiter: str = OutputField(example_values=[","])
    hash: float = OutputField(example_values=[3867657808])
    id: float = OutputField(example_values=[350])
    max_age_seconds: float = OutputField(example_values=[86400])
    name: str = OutputField(example_values=["Child Processes"])
    parameter_definition: str | None = None
    value_type: str = OutputField(example_values=["String"])


class SelectsOutput(ActionOutput):
    filter: FilterOutput | None = None
    sensor: SensorOutput


class SensorReferencesOutput(ActionOutput):
    name: str = OutputField(example_values=["Child Processes"])
    real_ms_avg: float = OutputField(example_values=[0])
    start_char: float = OutputField(example_values=[4])


class ParseQuestionOutput(ActionOutput):
    expire_seconds: float = OutputField(example_values=[600])
    force_computer_id_flag: float | None = None
    from_canonical_text: float = OutputField(example_values=[0])
    group: str = OutputField(
        cef_types=["taniumrest group definition"],
        example_values=["{ group id object }"],
    )
    question_text: str = OutputField(
        column_name="PARSED QUESTION",
        cef_types=["taniumrest question text"],
        example_values=["Get Child Processes from all machines"],
    )
    score: float = OutputField(example_values=[7082])
    selects: list[SelectsOutput] | None = None
    sensor_references: list[SensorReferencesOutput] | None = None
    skip_lock_flag: float | None = None


class ParseQuestionSummaryOutput(ActionOutput):
    number_of_parsed_questions: int = OutputField(example_values=[5])


@app.action(
    description="Parses the supplied text into a valid Tanium query string",
    action_type="investigate",
    verbose="<p>When asked a non-saved question in the <b>query_text</b> parameter, it will parse the given query and give a list of suggestions that are related to it.</p><p>For example, on the Tanium platform, if one were to just ask the question, 'all IP addresses,' Tanium will give the suggestions:<br><ul><li>Get Static IP Addresses from all machines</li><li>Get IP Routes from all machines</li><li>Get IP Address from all machines</li><li>Get IP Connections from all machines</li><li>Get IP Route Details from all machines</li><li>Get Network IP Gateway from all machines</li></ul><br>Tanium sorts this list, from most-related to least-related.</p>",
    view_handler=app.view_handler()(parse_question_view),
)
def parse_question(
    params: ParseQuestionParams, soar: SOARClient, asset: Asset
) -> list[ParseQuestionOutput]:
    client = TaniumClient(asset)
    client.ensure_authenticated()
    response = client.post(
        "/api/v2/parse_question",
        json={"text": params.query_text},
    )
    results = [
        ParseQuestionOutput.model_validate(item) for item in response.get("data", [])
    ]
    soar.set_summary(ParseQuestionSummaryOutput(number_of_parsed_questions=len(results)))
    return results


class ListQuestionsParams(Params):
    list_saved_questions: bool | None = Param(
        description="Retrieve Saved Questions", default=True
    )


class ArchiveOwnerOutput(ActionOutput):
    id: float = OutputField(example_values=[1])
    name: str = OutputField(example_values=["administrator"])


class ListQuestionsContentSetOutput(ActionOutput):
    id: float = OutputField(example_values=[7])
    name: str = OutputField(example_values=["Detect Service"])


class ContextGroupOutput(ActionOutput):
    id: float | None = None


class ManagementRightsGroupOutput(ActionOutput):
    id: float | None = None


class MetadataOutput(ActionOutput):
    admin_flag: bool | None = None
    name: str = OutputField(example_values=["SQPreference_Default"])
    value: str = OutputField(
        example_values=[
            '{"default_grid_zoom_level":0,"default_line_zoom_level":12,"default_tab":1,"merge_flag":0,"drilldown_flag":0}'
        ]
    )


class ListQuestionsModUserOutput(ActionOutput):
    display_name: str | None = None
    domain: str = OutputField(cef_types=["domain"])
    id: float = OutputField(example_values=[1])
    name: str = OutputField(example_values=["administrator"])


class PackagesOutput(ActionOutput):
    id: float = OutputField(example_values=[1])
    name: str = OutputField(example_values=["Distribute Tanium Standard Utilities"])


class QuestionOutput(ActionOutput):
    id: float = OutputField(
        cef_types=["taniumrest question id"], example_values=[56071]
    )


class SavedQuestionOutput(ActionOutput):
    id: float = OutputField(example_values=[15])


class ListQuestionsUserOutput(ActionOutput):
    deleted_flag: bool | None = None
    id: float = OutputField(example_values=[1])
    name: str = OutputField(example_values=["administrator"])


class ListQuestionsOutput(ActionOutput):
    action_tracking_flag: bool | None = None
    archive_enabled_flag: bool | None = None
    archive_owner: ArchiveOwnerOutput | None = None
    content_set: ListQuestionsContentSetOutput | None = None
    context_group: ContextGroupOutput | None = None
    expiration: str = OutputField(example_values=["2001-01-01T00:00:00Z"])
    expire_seconds: float = OutputField(example_values=[600])
    hidden_flag: bool | None = None
    id: float = OutputField(cef_types=["taniumrest question id"], example_values=[26])
    is_expired: bool | None = None
    issue_seconds: float = OutputField(example_values=[300])
    issue_seconds_never_flag: bool | None = None
    keep_seconds: float = OutputField(example_values=[0])
    management_rights_group: ManagementRightsGroupOutput | None = None
    metadata: list[MetadataOutput] | None = None
    mod_time: str = OutputField(example_values=["2019-02-11T21:22:25Z"])
    mod_user: ListQuestionsModUserOutput | None = None
    most_recent_question_id: float = OutputField(
        cef_types=["taniumrest question id"], example_values=[56071]
    )
    name: str = OutputField(example_values=["Detect Managed Unix Endpoints"])
    packages: list[PackagesOutput] | None = None
    public_flag: bool | None = None
    query_text: str = OutputField(
        cef_types=["taniumrest question text"],
        example_values=[
            "Get Detect Tools Status from all machines with ( Detect Tools Status contains engine version and Detect Tools Status contains Unix )"
        ],
    )
    question: QuestionOutput | None = None
    row_count_flag: bool | None = None
    saved_question: SavedQuestionOutput | None = None
    skip_lock_flag: bool | None = None
    sort_column: float = OutputField(example_values=[0])
    user: ListQuestionsUserOutput | None = None


@app.action(
    description="Retrieves either a history of the most recent questions or a list of saved questions",
    action_type="investigate",
    verbose="If the <b>list_saved_questions</b> parameter is true, this action will return a list of saved questions. If the flag is not set, this action will return the history of recently asked questions. As pagination is not implemented, the result(s) of the action will be the result(s) that are fetched in a single API call.",
)
def list_questions(
    params: ListQuestionsParams, soar: SOARClient, asset: Asset
) -> list[ListQuestionsOutput]:
    client = TaniumClient(asset)
    client.ensure_authenticated()

    if params.list_saved_questions is not False:
        endpoint = "/api/v2/saved_questions"
        response = client.get(endpoint)
        results = [
            ListQuestionsOutput.model_validate(q)
            for q in response.get("data", [])
            if q.get("id")
        ]
    else:
        endpoint = "/api/v2/questions"
        response = client.get(endpoint)
        seen_queries: set[str] = set()
        results = []
        for q in response.get("data", []):
            if q.get("id") and q.get("query_text") not in seen_queries:
                seen_queries.add(q.get("query_text"))
                results.append(ListQuestionsOutput.model_validate(q))

    soar.set_message(f"Num questions: {len(results)}")
    return results


class TerminateProcessParams(Params):
    action_name: str = Param(description="Name of the action")
    action_group: str = Param(description="Group of the action")
    package_name: str = Param(description="Package name that will be executed")
    package_parameters: str | None = Param(
        description="Package parameters of the corresponding package"
    )
    group_name: str | None = Param(
        description="Computer group name of which the process will be terminated"
    )
    distribute_seconds: float | None = Param(
        description="The number of seconds over which to deploy the action"
    )
    issue_seconds: float | None = Param(
        description="The number of seconds to reissue an action from the saved action"
    )
    expire_seconds: float = Param(
        description="The duration from the start time before the action expires",
        default=600,
    )


class TerminateProcessApproverOutput(ActionOutput):
    id: float = OutputField(example_values=[1])
    name: str = OutputField(example_values=["administrator"])


class TerminateProcessTargetGroupOutput(ActionOutput):
    id: float = OutputField(example_values=[3646])


class TerminateProcessLastActionOutput(ActionOutput):
    id: float = OutputField(example_values=[272936])
    start_time: str = OutputField(example_values=["Never"])
    target_group: TerminateProcessTargetGroupOutput


class TerminateProcessContentSetOutput(ActionOutput):
    id: float = OutputField(example_values=[9])
    name: str


class TerminateProcessFilesOutput(ActionOutput):
    bytes_downloaded: float
    bytes_total: float = OutputField(example_values=[39221])
    cache_status: str = OutputField(example_values=["Cached"])
    download_seconds: float
    download_start_time: str = OutputField(example_values=["2021-11-16T18:53:31Z"])
    hash: str = OutputField(
        example_values=[
            "b6c7534b828ff6e28f1467041a6f6f9a5ad7a7f4ac367c5425f16e249c77ec30"  # pragma: allowlist secret
        ]
    )
    id: float = OutputField(example_values=[73])
    last_download_progress_time: str = OutputField(
        example_values=["2021-11-16T18:53:31Z"]
    )
    name: str = OutputField(example_values=["clean-stale-tanium-client-data.vbs"])
    size: float = OutputField(example_values=[39221])
    source: str
    status: float = OutputField(example_values=[200])


class TerminateProcessModUserOutput(ActionOutput):
    display_name: str
    domain: str = OutputField(cef_types=["domain"])
    id: float = OutputField(example_values=[0])
    name: str


class TerminateProcessVerifyGroupOutput(ActionOutput):
    id: float = OutputField(example_values=[0])


class TerminateProcessPackageSpecOutput(ActionOutput):
    available_time: str = OutputField(example_values=["2001-01-01T00:00:00Z"])
    command: str = OutputField(
        example_values=["cmd /c mkdir C:\\Users\\Administrator\\some_dir\\"]
    )
    command_timeout: float = OutputField(example_values=[600])
    content_set: TerminateProcessContentSetOutput
    creation_time: str = OutputField(example_values=["2001-01-01T00:00:00Z"])
    deleted_flag: bool
    display_name: str
    expire_seconds: float = OutputField(example_values=[3600])
    files: list[TerminateProcessFilesOutput]
    hidden_flag: bool
    id: float = OutputField(column_name="PACKAGE ID", example_values=[600])
    last_modified_by: str
    last_update: str = OutputField(example_values=["2019-09-18T04:53:58Z"])
    mod_user: TerminateProcessModUserOutput | None = None
    modification_time: str = OutputField(example_values=["2001-01-01T00:00:00Z"])
    name: str = OutputField(column_name="PACKAGE NAME", example_values=["terminate process"])
    process_group_flag: bool
    skip_lock_flag: bool
    source_hash: str = OutputField(
        cef_types=["sha256"],
        example_values=[
            "b75af868db6d80c0e603ce8827146e2e44f2728c6ae98fd6082003412cf3a207"  # pragma: allowlist secret
        ],
    )
    source_hash_changed_flag: bool
    source_id: float = OutputField(example_values=[221])
    verify_expire_seconds: float = OutputField(example_values=[3600])
    verify_group: TerminateProcessVerifyGroupOutput
    verify_group_id: float = OutputField(example_values=[0])


class TerminateProcessUserOutput(ActionOutput):
    id: float = OutputField(example_values=[1])
    name: str = OutputField(example_values=["administrator"])


class TerminateProcessOutput(ActionOutput):
    status_display: str = OutputField(column_name="STATUS", example_values=["success"])
    id: float = OutputField(column_name="ACTION ID", example_values=[523])
    name: str = OutputField(column_name="NAME", example_values=["test terminate process"])
    expire_seconds: float = OutputField(column_name="EXPIRE SECONDS", example_values=[600])
    start_time: str = OutputField(column_name="START TIME", example_values=["2019-09-18T04:53:58Z"])
    issue_seconds: float = OutputField(column_name="ISSUE SECONDS", example_values=[0])
    distribute_seconds: float = OutputField(column_name="DISTRIBUTE SECONDS", example_values=[0])
    end_time: str = OutputField(column_name="END TIME", example_values=["Never"])
    package_spec: TerminateProcessPackageSpecOutput
    action_group_id: float = OutputField(example_values=[151])
    approved_flag: bool
    approver: TerminateProcessApproverOutput
    comment: str
    creation_time: str = OutputField(example_values=["2019-09-18T04:53:58Z"])
    issue_count: float = OutputField(example_values=[0])
    last_action: TerminateProcessLastActionOutput
    last_start_time: str = OutputField(example_values=["Never"])
    next_start_time: str = OutputField(example_values=["Never"])
    policy_flag: bool
    public_flag: bool
    start_now_flag: bool
    status: float = OutputField(example_values=[0])
    target_group: TerminateProcessTargetGroupOutput
    user: TerminateProcessUserOutput
    user_start_time: str = OutputField(example_values=["2001-01-01T00:00:00Z"])


@app.action(
    description="Kill a running process of the devices registered on the Tanium server",
    action_type="generic",
    read_only=False,
    view_handler=app.view_handler()(terminate_process_view),
)
def terminate_process(
    params: TerminateProcessParams, soar: SOARClient, asset: Asset
) -> TerminateProcessOutput:
    client = TaniumClient(asset)
    client.ensure_authenticated()
    result = client.execute_action_support(
        action_name=params.action_name,
        action_group=params.action_group,
        package_name=params.package_name,
        expire_seconds=int(params.expire_seconds),
        package_parameters=params.package_parameters,
        group_name=params.group_name,
        distribute_seconds=int(params.distribute_seconds)
        if params.distribute_seconds is not None
        else None,
        issue_seconds=int(params.issue_seconds)
        if params.issue_seconds is not None
        else None,
    )
    soar.set_message("Successfully executed the action")
    output = TerminateProcessOutput.model_validate(result)
    output.status_display = "success"
    return output


class ExecuteActionParams(Params):
    action_name: str = Param(description="Creates a name for the action executed")
    action_group: str = Param(description="Group of the action", default="Default")
    package_name: str = Param(description="Name of the Tanium package to be executed")
    package_parameters: str | None = Param(
        description='Parameter inputs of the corresponding package. Provide JSON format (i.e. {"$1": "Standard_Collection", "$2": "SCP"})'
    )
    group_name: str | None = Param(
        description="The Tanium Computer Group name on which the action will be executed. If left blank, will execute on all registered IP addresses/hostnames in your Tanium instance",
        primary=True,
        cef_types=["taniumrest group definition"],
    )
    distribute_seconds: float | None = Param(
        description="The number of seconds over which to deploy the action"
    )
    issue_seconds: float | None = Param(
        description="The number of seconds to reissue an action from the saved action"
    )
    expire_seconds: float = Param(
        description="The duration from the start time before the action expires",
        default=600,
    )


class ExecuteActionApproverOutput(ActionOutput):
    id: float = OutputField(example_values=[1])
    name: str = OutputField(example_values=["administrator"])


class ExecuteActionTargetGroupOutput(ActionOutput):
    id: float = OutputField(example_values=[3614])


class ExecuteActionLastActionOutput(ActionOutput):
    id: float = OutputField(example_values=[272568])
    start_time: str = OutputField(example_values=["Never"])
    target_group: ExecuteActionTargetGroupOutput


class ExecuteActionContentSetOutput(ActionOutput):
    id: float = OutputField(example_values=[2])
    name: str


class ExecuteActionFilesOutput(ActionOutput):
    bytes_downloaded: float
    bytes_total: float = OutputField(example_values=[39221])
    cache_status: str = OutputField(example_values=["Cached"])
    download_seconds: float
    download_start_time: str = OutputField(example_values=["2021-11-16T18:53:31Z"])
    hash: str = OutputField(
        example_values=[
            "b6c7534b828ff6e28f1467041a6f6f9a5ad7a7f4ac367c5425f16e249c77ec30"  # pragma: allowlist secret
        ]
    )
    id: float = OutputField(example_values=[73])
    last_download_progress_time: str = OutputField(
        example_values=["2021-11-16T18:53:31Z"]
    )
    name: str = OutputField(example_values=["clean-stale-tanium-client-data.vbs"])
    size: float = OutputField(example_values=[39221])
    source: str
    status: float = OutputField(example_values=[200])


class ExecuteActionModUserOutput(ActionOutput):
    display_name: str
    domain: str = OutputField(cef_types=["domain"])
    id: float = OutputField(example_values=[0])
    name: str


class ParametersOutput(ActionOutput):
    key: str = OutputField(example_values=["$1"])
    type: float = OutputField(example_values=[0])
    value: str = OutputField(example_values=["TestDirectory"])


class ExecuteActionVerifyGroupOutput(ActionOutput):
    id: float = OutputField(example_values=[0])


class ExecuteActionPackageSpecOutput(ActionOutput):
    available_time: str = OutputField(example_values=["2001-01-01T00:00:00Z"])
    command: str = OutputField(
        example_values=[
            'cmd /c mkdir C:\\Users\\Administrator\\test123\\"TestDirectory"'
        ]
    )
    command_timeout: float = OutputField(example_values=[600])
    content_set: ExecuteActionContentSetOutput
    creation_time: str = OutputField(example_values=["2001-01-01T00:00:00Z"])
    deleted_flag: bool
    display_name: str
    expire_seconds: float = OutputField(example_values=[3600])
    files: list[ExecuteActionFilesOutput]
    hidden_flag: bool
    id: float = OutputField(column_name="PACKAGE ID", example_values=[559])
    last_modified_by: str
    last_update: str = OutputField(example_values=["2019-09-16T07:43:57Z"])
    mod_user: ExecuteActionModUserOutput | None = None
    modification_time: str = OutputField(example_values=["2001-01-01T00:00:00Z"])
    name: str = OutputField(column_name="PACKAGE NAME", example_values=["make directory"])
    parameter_definition: str
    parameters: list[ParametersOutput] | None = None
    process_group_flag: bool
    skip_lock_flag: bool
    source_hash: str = OutputField(
        cef_types=["sha256"],
        example_values=[
            "d36e609e026380ce117388858503384ecd50f8fb9321ccaeab9647b4131cc7a7"  # pragma: allowlist secret
        ],
    )
    source_hash_changed_flag: bool
    source_id: float = OutputField(example_values=[500])
    verify_expire_seconds: float = OutputField(example_values=[3600])
    verify_group: ExecuteActionVerifyGroupOutput
    verify_group_id: float = OutputField(example_values=[0])


class ExecuteActionUserOutput(ActionOutput):
    id: float = OutputField(example_values=[1])
    name: str = OutputField(example_values=["administrator"])


class ExecuteActionOutput(ActionOutput):
    status_display: str = OutputField(column_name="STATUS", example_values=["success"])
    id: float = OutputField(column_name="ACTION ID", cef_types=["taniumrest question id"], example_values=[482])
    name: str = OutputField(column_name="NAME", example_values=["test action start 7"])
    expire_seconds: float = OutputField(column_name="EXPIRE SECONDS", example_values=[600])
    start_time: str = OutputField(column_name="START TIME", example_values=["2019-09-16T07:43:57Z"])
    issue_seconds: float = OutputField(column_name="ISSUE SECONDS", example_values=[0])
    distribute_seconds: float = OutputField(column_name="DISTRIBUTE SECONDS", example_values=[0])
    end_time: str = OutputField(column_name="END TIME", example_values=["Never"])
    package_spec: ExecuteActionPackageSpecOutput
    action_group_id: float = OutputField(example_values=[151])
    approved_flag: bool
    approver: ExecuteActionApproverOutput
    comment: str
    creation_time: str = OutputField(example_values=["2019-09-16T07:43:57Z"])
    issue_count: float = OutputField(example_values=[0])
    last_action: ExecuteActionLastActionOutput
    last_start_time: str = OutputField(example_values=["Never"])
    next_start_time: str = OutputField(example_values=["Never"])
    policy_flag: bool
    public_flag: bool
    start_now_flag: bool
    status: float = OutputField(example_values=[0])
    target_group: ExecuteActionTargetGroupOutput
    user: ExecuteActionUserOutput
    user_start_time: str = OutputField(example_values=["2001-01-01T00:00:00Z"])


@app.action(
    description="Execute an action on the Tanium server",
    action_type="generic",
    read_only=False,
    verbose="<li>See top-level app documentation for example parameters.</li><li>If a parameterized package is used for executing an action all the parameters must be provided with correct and unique keys. If any key is repeated then the value of that key will be overwritten.</li><li>If the <b>issue_seconds</b> parameter is provided, then the action will respawn after a time interval provided in the <b>issue_seconds</b> parameter.</li>",
    view_handler=app.view_handler()(execute_action_view),
)
def execute_action(
    params: ExecuteActionParams, soar: SOARClient, asset: Asset
) -> ExecuteActionOutput:
    client = TaniumClient(asset)
    client.ensure_authenticated()
    result = client.execute_action_support(
        action_name=params.action_name,
        action_group=params.action_group,
        package_name=params.package_name,
        expire_seconds=int(params.expire_seconds),
        package_parameters=params.package_parameters,
        group_name=params.group_name,
        distribute_seconds=int(params.distribute_seconds)
        if params.distribute_seconds is not None
        else None,
        issue_seconds=int(params.issue_seconds)
        if params.issue_seconds is not None
        else None,
    )
    soar.set_message("Successfully executed the action")
    output = ExecuteActionOutput.model_validate(result)
    output.status_display = "success"
    return output


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
    timeout_seconds: float = Param(
        description="The number of seconds before the question expires (manual query only)",
        default=600,
    )
    wait_for_results_processing: bool | None = Param(
        description="Flag to wait for endpoint to return full results", default=False
    )
    return_when_n_results_available: float | None = Param(
        description="Return results as soon as 'n' answers are available"
    )
    wait_for_n_results_available: float | None = Param(
        description="Wait until 'n' results are present, even if hit the percent complete threshold"
    )


class RunQueryColumnsOutput(ActionOutput):
    hash: float = OutputField(example_values=[3112892791])
    name: str = OutputField(example_values=["DNS Server"])
    type: float = OutputField(example_values=[5])


class RunQueryCellOutput(ActionOutput):
    text: str = OutputField(example_values=["192.168.1.1"])


class RunQueryRowsOutput(ActionOutput):
    cid: float = OutputField(example_values=[0])
    data: list[RunQueryCellOutput]
    id: float = OutputField(example_values=[1306085003])


class RunQueryResultSetsOutput(ActionOutput):
    age: float = OutputField(example_values=[0])
    archived_question_id: float = OutputField(example_values=[0])
    cache_id: str = OutputField(example_values=["2668614289"])
    columns: list[RunQueryColumnsOutput]
    error_count: float = OutputField(example_values=[0])
    estimated_total: float = OutputField(example_values=[2])
    expiration: float = OutputField(example_values=[0])
    expire_seconds: float = OutputField(example_values=[0])
    filtered_row_count: float = OutputField(example_values=[1])
    filtered_row_count_machines: float = OutputField(example_values=[1])
    id: float = OutputField(
        cef_types=["taniumrest question id"], example_values=[58377]
    )
    issue_seconds: float = OutputField(example_values=[0])
    item_count: float = OutputField(example_values=[1])
    mr_passed: float = OutputField(example_values=[1])
    mr_tested: float = OutputField(example_values=[2])
    no_results_count: float = OutputField(example_values=[0])
    passed: float = OutputField(example_values=[1])
    question_id: float = OutputField(
        cef_types=["taniumrest question id"], example_values=[58377]
    )
    report_count: float = OutputField(example_values=[2])
    row_count: float = OutputField(example_values=[1])
    row_count_machines: float = OutputField(example_values=[1])
    rows: list[RunQueryRowsOutput]
    saved_question_id: float = OutputField(example_values=[0])
    seconds_since_issued: float = OutputField(example_values=[0])
    select_count: float = OutputField(example_values=[1])
    tested: float = OutputField(example_values=[1])


class RunQueryDataOutput(ActionOutput):
    max_available_age: str | None = None
    now: str = OutputField(example_values=["2019/07/24 07:53:06 GMT-0000"])
    result_sets: list[RunQueryResultSetsOutput]


class RunQueryOutput(ActionOutput):
    data: RunQueryDataOutput


class RunQuerySummaryOutput(ActionOutput):
    number_of_rows: int = OutputField(example_values=[35])


@app.action(
    description="Run a search query on the devices registered on the Tanium server",
    action_type="investigate",
    verbose="See top-level app documentation for example parameters. For manual questions only, the action waits for <b>timeout_seconds</b> provided by the user in intervals of 5 seconds to fetch the results. The action is a success as soon as the results are retrieved or else it will timeout and fail. As pagination is not implemented, the result(s) of the action will be the result(s) that are fetched in a single API call. If an endpoint takes longer than usual to evaluate a sensor, it might initially supply the answer[current results unavailable] to the answer message that it passes along the linear chain and ultimately to the Tanium Server. However, the sensor process continues on the endpoint after supplying that initial answer and, upon completing the process, the endpoint sends its updated answer. Reference Link: ~https://docs.tanium.com/interact/interact/results.html.",
    view_handler=app.view_handler()(run_query_view),
)
def run_query(params: RunQueryParams, soar: SOARClient, asset: Asset) -> RunQueryOutput:
    client = TaniumClient(asset)
    client.ensure_authenticated()

    results_percentage = asset.results_percentage or 99.0
    timeout_seconds = params.timeout_seconds
    wait_for_results_processing = bool(params.wait_for_results_processing)
    return_when_n = (
        int(params.return_when_n_results_available)
        if params.return_when_n_results_available is not None
        else None
    )
    wait_for_n = (
        int(params.wait_for_n_results_available)
        if params.wait_for_n_results_available is not None
        else None
    )

    if (
        return_when_n is not None
        and wait_for_n is not None
        and return_when_n < wait_for_n
    ):
        from soar_sdk.exceptions import ActionFailure

        raise ActionFailure(
            "'return_when_n_results_available' must be greater than or equal to 'wait_for_n_results_available'"
        )

    if params.is_saved_question:
        sq_response = client.get(f"/api/v2/saved_questions/by-name/{params.query_text}")
        sq_data = sq_response.get("data")
        if not sq_data:
            raise ActionFailure(
                f"No saved question exists with name '{params.query_text}'"
            )
        sq = client.get_single(sq_data, "saved question")
        response = client.poll_saved_question_results(
            saved_question_id=sq["id"],
            timeout_seconds=timeout_seconds,
            results_percentage=results_percentage,
            wait_for_results_processing=wait_for_results_processing,
            return_when_n_results_available=return_when_n,
            wait_for_n_results_available=wait_for_n,
        )
    else:
        group_context: dict | None = None
        if params.group_name:
            grp_response = client.get(f"/api/v2/groups/by-name/{params.group_name}")
            grp_data = grp_response.get("data")
            if not grp_data:
                raise ActionFailure(f"No group exists with name '{params.group_name}'")
            grp = client.get_single(grp_data, "group")
            group_context = {"context_group": {"id": grp["id"]}}

        question_data = client.parse_and_validate_question(
            params.query_text, group_context
        )
        question_data["expire_seconds"] = int(timeout_seconds)

        post_response = client.post("/api/v2/questions", json=question_data)
        question_id = post_response.get("data", {}).get("id")

        response = client.poll_question_results(
            question_id=question_id,
            timeout_seconds=timeout_seconds,
            results_percentage=results_percentage,
            wait_for_results_processing=wait_for_results_processing,
            return_when_n_results_available=return_when_n,
            wait_for_n_results_available=wait_for_n,
        )

    output = RunQueryOutput.model_validate(response)
    number_of_rows = sum(rs.row_count for rs in output.data.result_sets)
    soar.set_summary(RunQuerySummaryOutput(number_of_rows=int(number_of_rows)))
    return output


class CreateGroupParams(Params):
    group_name: str = Param(
        description="Name of the Tanium Computer Group to create",
        primary=True,
        cef_types=["taniumrest group name"],
    )
    computer_names: str | None = Param(
        description="Comma-separated hostnames or computer names to include in the group",
        cef_types=["host name"],
    )
    ip_addresses: str | None = Param(
        description="Comma-separated IP addresses to include in the group",
        cef_types=["ip"],
    )


class CreateGroupComputerSpecsOutput(ActionOutput):
    id: float = OutputField(example_values=[1234])
    computer_name: str = OutputField(cef_types=["host name"], example_values=["host1"])
    ip_address: str = OutputField(cef_types=["ip"], example_values=["10.20.30.40"])


class CreateGroupOutput(ActionOutput):
    id: float = OutputField(cef_types=["taniumrest group id"], example_values=[1234])
    name: str = OutputField(
        cef_types=["taniumrest group name"], example_values=["manual-group-1"]
    )
    deleted_flag: bool = OutputField(example_values=[False])
    filter_flag: bool = OutputField(example_values=[False])
    management_rights_flag: bool = OutputField(example_values=[False])
    computer_specs: list[CreateGroupComputerSpecsOutput]


@app.action(
    description="Create a Tanium manual computer group from hostnames and IP addresses",
    action_type="generic",
    read_only=False,
)
def create_group(
    params: CreateGroupParams, soar: SOARClient, asset: Asset
) -> CreateGroupOutput:
    from soar_sdk.exceptions import ActionFailure

    client = TaniumClient(asset)
    client.ensure_authenticated()

    group_name = params.group_name.strip()
    computer_names = [
        v.strip() for v in (params.computer_names or "").split(",") if v.strip()
    ]
    ip_addresses = [
        v.strip() for v in (params.ip_addresses or "").split(",") if v.strip()
    ]

    if not computer_names and not ip_addresses:
        raise ActionFailure(
            "Please provide at least one value in either 'computer_names' or 'ip_addresses'"
        )

    computer_specs: list[dict] = [{"computer_name": n} for n in computer_names]
    computer_specs.extend({"ip_address": ip} for ip in ip_addresses)

    response = client.post(
        "/api/v2/computer_groups",
        json={"name": group_name, "computer_specs": computer_specs},
    )
    result = response.get("data")
    if not isinstance(result, dict):
        raise ActionFailure("Unexpected response format while creating the group")
    return CreateGroupOutput.model_validate(result)


class FindGroupsParams(Params):
    computer_names: str | None = Param(
        description="Comma-separated hostnames or computer names used to find matching groups",
        cef_types=["host name"],
    )
    ip_addresses: str | None = Param(
        description="Comma-separated IP addresses used to find matching groups",
        cef_types=["ip"],
    )


class FindGroupsComputerSpecsOutput(ActionOutput):
    id: float = OutputField(example_values=[1234])
    computer_name: str = OutputField(cef_types=["host name"], example_values=["host1"])
    ip_address: str = OutputField(cef_types=["ip"], example_values=["10.20.30.40"])


class FindGroupsOutput(ActionOutput):
    id: float = OutputField(cef_types=["taniumrest group id"], example_values=[1234])
    name: str = OutputField(
        cef_types=["taniumrest group name"], example_values=["manual-group-1"]
    )
    deleted_flag: bool = OutputField(example_values=[False])
    filter_flag: bool = OutputField(example_values=[False])
    management_rights_flag: bool = OutputField(example_values=[False])
    computer_specs: list[FindGroupsComputerSpecsOutput]


@app.action(
    description="Find Tanium manual computer groups matching hostnames or IP addresses",
    action_type="investigate",
)
def find_groups(
    params: FindGroupsParams, soar: SOARClient, asset: Asset
) -> list[FindGroupsOutput]:
    from soar_sdk.exceptions import ActionFailure

    client = TaniumClient(asset)
    client.ensure_authenticated()

    computer_names = [
        v.strip() for v in (params.computer_names or "").split(",") if v.strip()
    ]
    ip_addresses = [
        v.strip() for v in (params.ip_addresses or "").split(",") if v.strip()
    ]

    if not computer_names and not ip_addresses:
        raise ActionFailure(
            "Please provide at least one value in either 'computer_names' or 'ip_addresses'"
        )

    response = client.get("/api/v2/computer_groups")
    response_data = response.get("data")
    groups: list[dict] = (
        [response_data] if isinstance(response_data, dict) else (response_data or [])
    )

    requested_names = {n.lower() for n in computer_names}
    requested_ips = set(ip_addresses)

    matches = []
    for group in groups:
        if not isinstance(group, dict) or group.get("deleted_flag"):
            continue
        group_names: set[str] = set()
        group_ips: set[str] = set()
        for spec in group.get("computer_specs") or []:
            if spec.get("computer_name"):
                group_names.add(str(spec["computer_name"]).strip().lower())
            if spec.get("ip_address"):
                group_ips.add(str(spec["ip_address"]).strip())
        if requested_names.issubset(group_names) and requested_ips.issubset(group_ips):
            matches.append(group)

    return [FindGroupsOutput.model_validate(m) for m in matches]


class DeleteGroupParams(Params):
    group_id: float = Param(
        description="ID of the Tanium manual computer group to delete",
        primary=True,
        cef_types=["taniumrest group id"],
    )


class DeleteGroupOutput(ActionOutput):
    id: float = OutputField(cef_types=["taniumrest group id"], example_values=[1234])
    deleted_flag: bool = OutputField(example_values=[True])
    name: str = OutputField(
        cef_types=["taniumrest group name"], example_values=["manual-group-1"]
    )


@app.action(
    description="Delete a Tanium manual computer group by ID",
    action_type="generic",
    read_only=False,
)
def delete_group(
    params: DeleteGroupParams, soar: SOARClient, asset: Asset
) -> DeleteGroupOutput:
    client = TaniumClient(asset)
    client.ensure_authenticated()
    response = client.delete(f"/api/v2/computer_groups/{int(params.group_id)}")
    return DeleteGroupOutput.model_validate(response["data"])


class GetQuestionResultsParams(Params):
    question_id: float = Param(
        description="The ID of the question",
        primary=True,
        cef_types=["taniumrest question id"],
    )


class GetQuestionResultsColumnsOutput(ActionOutput):
    hash: float = OutputField(example_values=[3112892791])
    name: str = OutputField(example_values=["DNS Server"])
    type: float = OutputField(example_values=[5])


class GetQuestionResultsCellOutput(ActionOutput):
    text: str = OutputField(example_values=["192.168.1.1"])


class GetQuestionResultsRowsOutput(ActionOutput):
    cid: float = OutputField(example_values=[0])
    data: list[GetQuestionResultsCellOutput]
    id: float = OutputField(example_values=[1306085003])


class GetQuestionResultsResultSetsOutput(ActionOutput):
    age: float = OutputField(example_values=[0])
    archived_question_id: float = OutputField(example_values=[0])
    cache_id: str = OutputField(example_values=["2668614289"])
    columns: list[GetQuestionResultsColumnsOutput]
    error_count: float = OutputField(example_values=[0])
    estimated_total: float = OutputField(example_values=[2])
    expiration: float = OutputField(example_values=[0])
    expire_seconds: float = OutputField(example_values=[0])
    filtered_row_count: float = OutputField(example_values=[1])
    filtered_row_count_machines: float = OutputField(example_values=[1])
    id: float = OutputField(
        cef_types=["taniumrest question id"], example_values=[58377]
    )
    issue_seconds: float = OutputField(example_values=[0])
    item_count: float = OutputField(example_values=[1])
    mr_passed: float = OutputField(example_values=[1])
    mr_tested: float = OutputField(example_values=[2])
    no_results_count: float = OutputField(example_values=[0])
    passed: float = OutputField(example_values=[1])
    question_id: float = OutputField(
        cef_types=["taniumrest question id"], example_values=[58377]
    )
    report_count: float = OutputField(example_values=[2])
    row_count: float = OutputField(example_values=[1])
    row_count_machines: float = OutputField(example_values=[1])
    rows: list[GetQuestionResultsRowsOutput]
    saved_question_id: float = OutputField(example_values=[0])
    seconds_since_issued: float = OutputField(example_values=[0])
    select_count: float = OutputField(example_values=[1])
    tested: float = OutputField(example_values=[1])


class GetQuestionResultsDataOutput(ActionOutput):
    max_available_age: str | None = None
    now: str = OutputField(example_values=["2019/07/24 07:53:06 GMT-0000"])
    result_sets: list[GetQuestionResultsResultSetsOutput]


class GetQuestionResultsOutput(ActionOutput):
    data: GetQuestionResultsDataOutput


@app.action(
    description="Return the results for an already asked question",
    action_type="investigate",
    view_handler=app.view_handler()(get_question_results_view),
)
def get_question_results(
    params: GetQuestionResultsParams, soar: SOARClient, asset: Asset
) -> GetQuestionResultsOutput:
    client = TaniumClient(asset)
    client.ensure_authenticated()
    response = client.get(f"/api/v2/result_data/question/{int(params.question_id)}")
    output = GetQuestionResultsOutput.model_validate(response)
    row_count = sum(
        rs.row_count for rs in output.data.result_sets
    )
    soar.set_message(f"Number of rows: {int(row_count)}")
    return output


class TaniumMakeRequestParams(MakeRequestParams):
    endpoint: str = Param(
        description=(
            "Tanium REST API endpoint, relative to the base URL. "
            "Example: '/api/v2/saved_questions' or '/api/v2/sensors/by-name/IP%20Address'"
        ),
        required=True,
        primary=True,
    )


@app.make_request()
def make_request(
    params: TaniumMakeRequestParams, soar: SOARClient, asset: Asset
) -> MakeRequestOutput:
    """Make a generic HTTP request to the Tanium REST API."""
    from soar_sdk.exceptions import ActionFailure

    if params.endpoint.startswith(("http://", "https://")):
        raise ActionFailure(
            f"Invalid endpoint '{params.endpoint}'. "
            "Provide a relative path only (e.g. '/api/v2/saved_questions'). "
            "The base URL is taken from the asset configuration."
        )

    client = TaniumClient(asset)
    client.ensure_authenticated()

    endpoint = (
        params.endpoint if params.endpoint.startswith("/") else f"/{params.endpoint}"
    )

    extra_headers: dict = {}
    if params.headers:
        import json as _json

        try:
            extra_headers = _json.loads(params.headers)
        except (_json.JSONDecodeError, TypeError) as e:
            raise ActionFailure(f"Invalid JSON in 'headers' parameter: {e}") from e

    query_params = None
    if params.query_parameters:
        import json as _json

        try:
            query_params = _json.loads(params.query_parameters)
        except (_json.JSONDecodeError, TypeError):
            query_params = params.query_parameters

    json_body = None
    raw_body = None
    if params.body:
        import json as _json

        content_type = extra_headers.get("Content-Type", "application/json").lower()
        if "json" in content_type:
            try:
                json_body = _json.loads(params.body)
            except (_json.JSONDecodeError, TypeError) as e:
                raise ActionFailure(f"Invalid JSON in 'body' parameter: {e}") from e
        else:
            raw_body = params.body

    import httpx

    timeout = params.timeout or 30
    verify = (
        params.verify_ssl if params.verify_ssl is not None else asset.verify_server_cert
    )

    url = f"{asset.base_url.strip('/\\')}{endpoint}"
    request_headers = client._headers()
    request_headers.update(extra_headers)

    try:
        with httpx.Client(verify=bool(verify)) as http_client:
            response = http_client.request(
                method=params.http_method,
                url=url,
                headers=request_headers,
                params=query_params,
                json=json_body,
                content=raw_body,
                timeout=timeout,
            )
    except httpx.ConnectError as e:
        raise ActionFailure(
            f"Could not connect to '{asset.base_url}'. "
            "Check that the Base URL is correct and the Tanium server is reachable. "
            f"Detail: {e}"
        ) from e
    except httpx.TimeoutException as e:
        raise ActionFailure(f"Request timed out after {timeout}s: {e}") from e

    return MakeRequestOutput(
        status_code=response.status_code,
        response_body=response.text,
    )


if __name__ == "__main__":
    app.cli()
