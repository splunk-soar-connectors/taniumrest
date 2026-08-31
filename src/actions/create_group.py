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
from ..constants import API_V2_COMPUTER_GROUPS
from ..tanium_client import get_client


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


class CreateGroupComputerSpecsOutput(PermissiveActionOutput):
    id: float | None = OutputField(example_values=[1234])
    computer_name: str | None = OutputField(
        cef_types=["host name"], example_values=["host1"]
    )
    ip_address: str | None = OutputField(
        cef_types=["ip"], example_values=["10.20.30.40"]
    )


class CreateGroupOutput(PermissiveActionOutput):
    id: float | None = OutputField(
        column_name="GROUP ID", cef_types=["taniumrest group id"], example_values=[1234]
    )
    name: str | None = OutputField(
        column_name="GROUP NAME",
        cef_types=["taniumrest group name"],
        example_values=["manual-group-1"],
    )
    deleted_flag: bool | None = OutputField(example_values=[False])
    filter_flag: bool | None = OutputField(example_values=[False])
    management_rights_flag: bool | None = OutputField(example_values=[False])
    computer_specs: list[CreateGroupComputerSpecsOutput] | None = None


class CreateGroupSummaryOutput(ActionOutput):
    group_id: float | None = OutputField(
        cef_types=["taniumrest group id"], example_values=[1234]
    )
    group_name: str = OutputField(
        cef_types=["taniumrest group name"], example_values=["manual-group-1"]
    )
    computer_name_count: int = OutputField(example_values=[1])
    ip_address_count: int = OutputField(example_values=[0])


def create_group(
    params: CreateGroupParams, soar: SOARClient, asset: Asset
) -> CreateGroupOutput:
    group_name = params.group_name.strip()
    if not group_name:
        raise ActionFailure(
            "Please provide a non-empty value in the 'group_name' action parameter"
        )

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

    with get_client(asset) as client:
        response = client.request(
            "POST",
            API_V2_COMPUTER_GROUPS,
            json={"name": group_name, "computer_specs": computer_specs},
        )
    result = response.get("data")
    if not isinstance(result, dict):
        raise ActionFailure("Unexpected response format while creating the group")
    output = CreateGroupOutput.model_validate(result)
    soar.set_summary(
        CreateGroupSummaryOutput(
            group_id=output.id if output.id else None,
            group_name=output.name or group_name,
            computer_name_count=len(computer_names),
            ip_address_count=len(ip_addresses),
        )
    )
    soar.set_message("Successfully created the group")
    return output
