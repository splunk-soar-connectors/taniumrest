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
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.exceptions import ActionFailure
from soar_sdk.params import Param, Params

from ..asset import Asset
from ..constants import endpoint_computer_group
from ..tanium_client import get_client


class DeleteGroupParams(Params):
    group_id: int = Param(
        description="ID of the Tanium manual computer group to delete",
        primary=True,
        cef_types=["taniumrest group id"],
    )


class DeleteGroupOutput(ActionOutput):
    id: int = OutputField(
        column_name="GROUP ID", cef_types=["taniumrest group id"], example_values=[1234]
    )
    deleted_flag: bool = OutputField(column_name="DELETED", example_values=[True])
    name: str = OutputField(
        column_name="GROUP NAME",
        cef_types=["taniumrest group name"],
        example_values=["manual-group-1"],
    )


class DeleteGroupSummaryOutput(ActionOutput):
    group_id: int = OutputField(
        cef_types=["taniumrest group id"], example_values=[1234]
    )


def delete_group(
    params: DeleteGroupParams, soar: SOARClient, asset: Asset
) -> DeleteGroupOutput:
    if params.group_id < 0:
        raise ActionFailure(
            "Please provide a valid non-negative integer value in the 'group_id' action parameter"
        )
    if params.group_id == 0:
        raise ActionFailure(
            "Please provide a valid non-zero non-negative integer value in the 'group_id' action parameter"
        )

    with get_client(asset) as client:
        response = client.request("DELETE", endpoint_computer_group(params.group_id))
    output = DeleteGroupOutput.model_validate(response["data"])
    soar.set_summary(DeleteGroupSummaryOutput(group_id=output.id))
    soar.set_message("Successfully deleted the group")
    return output
