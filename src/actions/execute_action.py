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
from soar_sdk.action_results import (
    ActionOutput,
    ActionResult,
    OutputField,
    PermissiveActionOutput,
)
from soar_sdk.params import Param, Params

from ..asset import Asset
from ..tanium_client import get_client
from ._execution import run_action, validate_action_params
from ._polling import ActionPollResult, poll_action_completion


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
    distribute_seconds: int | None = Param(
        description="The number of seconds over which to deploy the action"
    )
    issue_seconds: int | None = Param(
        description="The number of seconds to reissue an action from the saved action"
    )
    expire_seconds: int = Param(
        description="The duration from the start time before the action expires",
        default=600,
    )
    wait_for_completion: bool = Param(
        description="Wait for Tanium endpoint execution to complete before returning",
        default=True,
    )


class ExecuteActionSummaryOutput(ActionOutput):
    saved_action_id: int | None = OutputField(example_values=[482])
    action_id: int | None = OutputField(example_values=[272568])
    action_status: str | None = OutputField(example_values=["active"])
    pending_approval: bool = OutputField(example_values=[False])
    completed_endpoint_count: int = OutputField(example_values=[2])
    failed_endpoint_count: int = OutputField(example_values=[0])
    running_endpoint_count: int = OutputField(example_values=[0])
    unknown_endpoint_count: int = OutputField(example_values=[0])
    expected_endpoint_count: int = OutputField(example_values=[2])


class ExecuteActionApproverOutput(PermissiveActionOutput):
    id: float | None = OutputField(example_values=[1])
    name: str | None = OutputField(example_values=["administrator"])


class ExecuteActionTargetGroupOutput(PermissiveActionOutput):
    id: float | None = OutputField(example_values=[3614])


class ExecuteActionLastActionOutput(PermissiveActionOutput):
    id: float | None = OutputField(example_values=[272568])
    start_time: str | None = OutputField(example_values=["Never"])
    target_group: ExecuteActionTargetGroupOutput | None = None


class ExecuteActionContentSetOutput(PermissiveActionOutput):
    id: float | None = OutputField(example_values=[2])
    name: str | None = None


class ExecuteActionFilesOutput(PermissiveActionOutput):
    bytes_downloaded: float | None = None
    bytes_total: float | None = OutputField(example_values=[39221])
    cache_status: str | None = OutputField(example_values=["Cached"])
    download_seconds: float | None = None
    download_start_time: str | None = OutputField(
        example_values=["2021-11-16T18:53:31Z"]
    )
    hash: str | None = OutputField(
        example_values=[
            "b6c7534b828ff6e28f1467041a6f6f9a5ad7a7f4ac367c5425f16e249c77ec30"  # pragma: allowlist secret
        ]
    )
    id: float | None = OutputField(example_values=[73])
    last_download_progress_time: str | None = OutputField(
        example_values=["2021-11-16T18:53:31Z"]
    )
    name: str | None = OutputField(
        example_values=["clean-stale-tanium-client-data.vbs"]
    )
    size: float | None = OutputField(example_values=[39221])
    source: str | None = None
    status: float | None = OutputField(example_values=[200])


class ExecuteActionModUserOutput(PermissiveActionOutput):
    display_name: str | None = None
    domain: str | None = OutputField(cef_types=["domain"])
    id: float | None = OutputField(example_values=[0])
    name: str | None = None


class ParametersOutput(PermissiveActionOutput):
    key: str | None = OutputField(example_values=["$1"])
    type: float | None = OutputField(example_values=[0])
    value: str | None = OutputField(example_values=["TestDirectory"])


class ExecuteActionVerifyGroupOutput(PermissiveActionOutput):
    id: float | None = OutputField(example_values=[0])


class ExecuteActionPackageSpecOutput(PermissiveActionOutput):
    available_time: str | None = OutputField(example_values=["2001-01-01T00:00:00Z"])
    command: str | None = OutputField(
        example_values=[
            'cmd /c mkdir C:\\Users\\Administrator\\test123\\"TestDirectory"'
        ]
    )
    command_timeout: float | None = OutputField(example_values=[600])
    content_set: ExecuteActionContentSetOutput | None = None
    creation_time: str | None = OutputField(example_values=["2001-01-01T00:00:00Z"])
    deleted_flag: bool | None = None
    display_name: str | None = None
    expire_seconds: float | None = OutputField(example_values=[3600])
    files: list[ExecuteActionFilesOutput] | None = None
    hidden_flag: bool | None = None
    id: float | None = OutputField(example_values=[559])
    last_modified_by: str | None = None
    last_update: str | None = OutputField(example_values=["2019-09-16T07:43:57Z"])
    mod_user: ExecuteActionModUserOutput | None = None
    modification_time: str | None = OutputField(example_values=["2001-01-01T00:00:00Z"])
    source_id: float | None = OutputField(
        column_name="PACKAGE ID", example_values=[500]
    )
    name: str | None = OutputField(
        column_name="PACKAGE NAME", example_values=["make directory"]
    )
    parameter_definition: str | None = None
    parameters: list[ParametersOutput] | None = None
    process_group_flag: bool | None = None
    skip_lock_flag: bool | None = None
    source_hash: str | None = OutputField(
        cef_types=["sha256"],
        example_values=[
            "d36e609e026380ce117388858503384ecd50f8fb9321ccaeab9647b4131cc7a7"  # pragma: allowlist secret
        ],
    )
    source_hash_changed_flag: bool | None = None
    verify_expire_seconds: float | None = OutputField(example_values=[3600])
    verify_group: ExecuteActionVerifyGroupOutput | None = None
    verify_group_id: float | None = OutputField(example_values=[0])


class ExecuteActionUserOutput(PermissiveActionOutput):
    id: float | None = OutputField(example_values=[1])
    name: str | None = OutputField(example_values=["administrator"])


class ExecuteActionOutput(PermissiveActionOutput):
    id: float | None = OutputField(
        column_name="ACTION ID",
        example_values=[482],
    )
    name: str | None = OutputField(
        column_name="NAME", example_values=["test action start 7"]
    )
    expire_seconds: float | None = OutputField(
        column_name="EXPIRE SECONDS", example_values=[600]
    )
    start_time: str | None = OutputField(
        column_name="START TIME", example_values=["2019-09-16T07:43:57Z"]
    )
    issue_seconds: float | None = OutputField(
        column_name="ISSUE SECONDS", example_values=[0]
    )
    distribute_seconds: float | None = OutputField(
        column_name="DISTRIBUTE SECONDS", example_values=[0]
    )
    end_time: str | None = OutputField(column_name="END TIME", example_values=["Never"])
    package_spec: ExecuteActionPackageSpecOutput | None = None
    action_group_id: float | None = OutputField(example_values=[151])
    approved_flag: bool | None = None
    approver: ExecuteActionApproverOutput | None = None
    comment: str | None = None
    creation_time: str | None = OutputField(example_values=["2019-09-16T07:43:57Z"])
    issue_count: float | None = OutputField(example_values=[0])
    last_action: ExecuteActionLastActionOutput | None = None
    last_start_time: str | None = OutputField(example_values=["Never"])
    next_start_time: str | None = OutputField(example_values=["Never"])
    policy_flag: bool | None = None
    public_flag: bool | None = None
    start_now_flag: bool | None = None
    status: float | None = OutputField(example_values=[0])
    target_group: ExecuteActionTargetGroupOutput | None = None
    user: ExecuteActionUserOutput | None = None
    user_start_time: str | None = OutputField(example_values=["2001-01-01T00:00:00Z"])


def _build_summary(poll_result: ActionPollResult) -> ExecuteActionSummaryOutput:
    return ExecuteActionSummaryOutput(
        saved_action_id=poll_result.saved_action_id,
        action_id=poll_result.action_id,
        action_status=poll_result.action_status,
        pending_approval=poll_result.pending_approval,
        completed_endpoint_count=poll_result.completed_endpoint_count,
        failed_endpoint_count=poll_result.failed_endpoint_count,
        running_endpoint_count=poll_result.running_endpoint_count,
        unknown_endpoint_count=poll_result.unknown_endpoint_count,
        expected_endpoint_count=poll_result.expected_endpoint_count,
    )


def execute_action(
    params: ExecuteActionParams, soar: SOARClient, asset: Asset
) -> ExecuteActionOutput:
    validate_action_params(
        params.expire_seconds, params.distribute_seconds, params.issue_seconds
    )
    with get_client(asset) as client:
        result = run_action(
            client,
            action_name=params.action_name,
            action_group=params.action_group,
            package_name=params.package_name,
            expire_seconds=params.expire_seconds,
            package_parameters=params.package_parameters,
            group_name=params.group_name,
            distribute_seconds=params.distribute_seconds,
            issue_seconds=params.issue_seconds,
        )
        if not params.wait_for_completion:
            soar.set_message("Successfully executed the action")
            return ExecuteActionOutput.model_validate(result)

        poll_result = poll_action_completion(client, result, params.expire_seconds)
        if poll_result.error:
            action_result = ActionResult(
                status=False,
                message=poll_result.error_message,
                param=params.model_dump(mode="json"),
            )
            action_result.add_data(result)
            action_result.set_summary(
                _build_summary(poll_result).model_dump(by_alias=True)
            )
            return action_result  # type: ignore[return-value]
    soar.set_summary(_build_summary(poll_result))
    soar.set_message(poll_result.message)
    return ExecuteActionOutput.model_validate(result)
