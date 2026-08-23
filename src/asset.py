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
from pydantic import model_validator
from soar_sdk.asset import AssetField, BaseAsset, FieldCategory
from soar_sdk.exceptions import ActionFailure


class Asset(BaseAsset):
    base_url: str = AssetField(
        description="Base URL (e.g. https://taniumserver)",
        category=FieldCategory.CONNECTIVITY,
    )
    api_token: str | None = AssetField(
        description="API Token",
        sensitive=True,
        category=FieldCategory.CONNECTIVITY,
    )
    username: str | None = AssetField(
        description="Username",
        category=FieldCategory.CONNECTIVITY,
    )
    password: str | None = AssetField(
        description="Password",
        sensitive=True,
        category=FieldCategory.CONNECTIVITY,
    )
    verify_server_cert: bool = AssetField(
        description="Verify Server Certificate",
        required=False,
        default=True,
        category=FieldCategory.CONNECTIVITY,
    )
    results_percentage: int | None = AssetField(
        description="Consider question results complete at (% out of 100)",
        default=99,
        category=FieldCategory.ACTION,
    )
    integration_header_value: str | None = AssetField(
        description="Optional value for the x-tanium-integration API header. Configure only when required by Tanium partner or test accounts.",
        category=FieldCategory.CONNECTIVITY,
    )

    @model_validator(mode="after")
    def _validate_base_url(self) -> "Asset":
        self.base_url = self.base_url.rstrip("/\\")
        if not self.base_url.startswith(("http://", "https://")):
            raise ActionFailure(
                "Please provide a valid Base URL that starts with 'http://' or 'https://'"
            )
        return self

    @model_validator(mode="after")
    def _validate_results_percentage(self) -> "Asset":
        pct = self.results_percentage
        if pct is not None and not (0 <= pct <= 100):
            raise ActionFailure(
                "Please provide a valid integer in range of 0-100 in 'results_percentage'"
            )
        return self
