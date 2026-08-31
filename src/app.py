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

from .actions import register_actions
from .asset import Asset
from .constants import API_V2_SAVED_QUESTIONS
from .tanium_client import get_client


def create_tanium_rest_soar_connector_app() -> App:
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
        """Validate the asset configuration for connectivity using supplied configuration."""
        with get_client(asset) as client:
            client.request("GET", API_V2_SAVED_QUESTIONS)

    return register_actions(app)


app: App = create_tanium_rest_soar_connector_app()


if __name__ == "__main__":
    app.cli()
