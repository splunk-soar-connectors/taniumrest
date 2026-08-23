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
from urllib.parse import quote

INTEGRATION_HEADER = "x-tanium-integration"
DEFAULT_TIMEOUT = 30

API_V2_ACTION_GROUPS_BY_NAME = "/api/v2/action_groups/by-name"
API_V2_ACTIONS = "/api/v2/actions"
API_V2_COMPUTER_GROUPS = "/api/v2/computer_groups"
API_V2_GROUPS_BY_NAME = "/api/v2/groups/by-name"
API_V2_PACKAGES_BY_NAME = "/api/v2/packages/by-name"
API_V2_PARSE_QUESTION = "/api/v2/parse_question"
API_V2_QUESTIONS = "/api/v2/questions"
API_V2_RESULT_DATA_ACTION = "/api/v2/result_data/action"
API_V2_RESULT_DATA_QUESTION = "/api/v2/result_data/question"
API_V2_RESULT_DATA_SAVED_QUESTION = "/api/v2/result_data/saved_question"
API_V2_SAVED_ACTIONS = "/api/v2/saved_actions"
API_V2_SAVED_QUESTIONS = "/api/v2/saved_questions"
API_V2_SAVED_QUESTIONS_BY_NAME = "/api/v2/saved_questions/by-name"
API_V2_SENSORS_BY_NAME = "/api/v2/sensors/by-name"
API_V2_SESSION_LOGIN = "/api/v2/session/login"


def endpoint_action(action_id: object) -> str:
    return f"{API_V2_ACTIONS}/{action_id}"


def endpoint_action_group_by_name(action_group: object) -> str:
    return f"{API_V2_ACTION_GROUPS_BY_NAME}/{_quote_path_value(action_group)}"


def endpoint_action_result_data(action_id: object) -> str:
    return f"{API_V2_RESULT_DATA_ACTION}/{action_id}"


def endpoint_computer_group(group_id: object) -> str:
    return f"{API_V2_COMPUTER_GROUPS}/{group_id}"


def endpoint_group_by_name(group_name: object) -> str:
    return f"{API_V2_GROUPS_BY_NAME}/{_quote_path_value(group_name)}"


def endpoint_package_by_name(package_name: object) -> str:
    return f"{API_V2_PACKAGES_BY_NAME}/{_quote_path_value(package_name)}"


def endpoint_question_result_data(question_id: object) -> str:
    return f"{API_V2_RESULT_DATA_QUESTION}/{question_id}"


def endpoint_saved_action(saved_action_id: object) -> str:
    return f"{API_V2_SAVED_ACTIONS}/{saved_action_id}"


def endpoint_saved_question_by_name(saved_question_name: object) -> str:
    return f"{API_V2_SAVED_QUESTIONS_BY_NAME}/{_quote_path_value(saved_question_name)}"


def endpoint_saved_question_result_data(saved_question_id: object) -> str:
    return f"{API_V2_RESULT_DATA_SAVED_QUESTION}/{saved_question_id}"


def endpoint_sensor_by_name(sensor_name: object) -> str:
    return f"{API_V2_SENSORS_BY_NAME}/{_quote_path_value(sensor_name)}"


def _quote_path_value(value: object) -> str:
    return quote(str(value), safe="")
