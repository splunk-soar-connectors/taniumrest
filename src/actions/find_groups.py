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


class FindGroupsParams(Params):
    computer_names: str | None = Param(
        description="Comma-separated hostnames or computer names used to find matching groups",
        cef_types=["host name"],
    )
    ip_addresses: str | None = Param(
        description="Comma-separated IP addresses used to find matching groups",
        cef_types=["ip"],
    )


class FindGroupsComputerSpecsOutput(PermissiveActionOutput):
    id: float | None = OutputField(example_values=[1234])
    computer_name: str | None = OutputField(
        cef_types=["host name"], example_values=["host1"]
    )
    ip_address: str | None = OutputField(
        cef_types=["ip"], example_values=["10.20.30.40"]
    )


class FindGroupsOutput(PermissiveActionOutput):
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
    computer_specs: list[FindGroupsComputerSpecsOutput] | None = None


class FindGroupsSummaryOutput(ActionOutput):
    total_groups: int = OutputField(example_values=[1])
    computer_name_count: int = OutputField(example_values=[1])
    ip_address_count: int = OutputField(example_values=[0])


def find_groups(
    params: FindGroupsParams, soar: SOARClient, asset: Asset
) -> list[FindGroupsOutput]:
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

    with get_client(asset) as client:
        response = client.request("GET", API_V2_COMPUTER_GROUPS)
    response_data = response.get("data")
    if isinstance(response_data, dict):
        groups = [response_data]
    elif isinstance(response_data, list):
        groups = response_data
    else:
        raise ActionFailure("Unexpected API response while fetching computer groups")

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
                group_names.add(spec["computer_name"].strip().lower())
            if spec.get("ip_address"):
                group_ips.add(str(spec["ip_address"]).strip())
        if requested_names.issubset(group_names) and requested_ips.issubset(group_ips):
            matches.append(group)

    results = [FindGroupsOutput.model_validate(m) for m in matches]
    soar.set_summary(
        FindGroupsSummaryOutput(
            total_groups=len(results),
            computer_name_count=len(computer_names),
            ip_address_count=len(ip_addresses),
        )
    )
    soar.set_message(f"Found {len(results)} matching group(s)")
    return results
