# File: taniumrest_consts.py
#
# Copyright (c) 2019-2024 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
TANIUMREST_SESSION_URL = "/api/v2/session/login"
TANIUMREST_GET_SAVED_QUESTIONS = "/api/v2/saved_questions"
TANIUMREST_GET_QUESTIONS = "/api/v2/questions"
TANIUMREST_GET_QUESTION_RESULTS = "/api/v2/result_data/question/{question_id}"
TANIUMREST_PARSE_QUESTION = "/api/v2/parse_question"
TANIUMREST_EXECUTE_ACTION = "/api/v2/saved_actions"
TANIUMREST_GET_ACTION_GROUP = "/api/v2/action_groups/by-name/{action_group}"
TANIUMREST_GET_GROUP = "/api/v2/groups/by-name/{group_name}"
TANIUMREST_GET_PACKAGE = "/api/v2/packages/by-name/{package}"
TANIUMREST_GET_SAVED_QUESTION = "/api/v2/saved_questions/by-name/{saved_question}"
TANIUMREST_GET_SENSOR_BY_NAME = "/api/v2/sensors/by-name/{sensor_name}"
TANIUMREST_GET_SAVED_QUESTION_RESULT = "/api/v2/result_data/saved_question/{saved_question_id}"
TANIUMREST_WAIT_SECONDS = 5
TANIUMREST_DEFAULT_TIMEOUT = 30  # in seconds
TANIUMREST_RESULTS_UNAVAILABLE = [
    "[current results unavailable]",
    "[current result unavailable]",
    "[results currently unavailable]"
]
TANIUMREST_PARAMETERS_WITHOUT_INPUT = ("com.tanium.components.parameters::SeparatorParameter")

# Constants relating to 'get_error_message_from_exception'
TANIUMREST_ERR_CODE_MSG = "Error code unavailable"
TANIUMREST_ERR_MSG_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters"
TANIUMREST_TYPE_ERR_MSG = "Error occurred while connecting to the Tanium Server. " \
    "Please check the asset configuration and|or action parameters"

TANIUMREST_NOT_ENOUGH_PARAMS = 'For parameters which you do not want to add value, please use double quotes("").' \
    'For more details refer to the documentation'
TANIUMREST_RESOURCE_NOT_EXIST = "No {1} exists with name {0}. " \
    "Also, please verify that your account has sufficient permissions to access the {1}s"

# Constants relating to 'validate_integer'
TANIUMREST_INVALID_INT_ERR_MSG = "Please provide a valid integer value in the {}"
TANIUMREST_INVALID_NON_NEG_INT_ERR_MSG = "Please provide a valid non-negative integer value in the {}"
TANIUMREST_INVALID_NON_NEG_NON_ZERO_ERR_MSG = "Please provide a valid non-zero non-negative integer value in the {}"
TANIUMREST_EXPIRE_SECONDS_KEY = "'expire_seconds' action parameter"
TANIUMREST_DISTRIBUTE_SECONDS_KEY = "'distribute_seconds' action parameter"
TANIUMREST_ISSUE_SECONDS_KEY = "'issue_seconds' action parameter"
TANIUMREST_TIMEOUT_SECONDS_KEY = "'timeout_seconds' action parameter"
TANIUMREST_RETURN_WHEN_N_RESULTS_AVAILABLE_KEY = "'return_when_n_results_available' action parameter"
TANIUMREST_WAIT_FOR_N_RESULTS_AVAILABLE_KEY = "'wait_for_n_results_available' action parameter"
TANIUMREST_RESULTS_PERCENTAGE_KEY = "'Consider question results complete at' configuration parameter"
TANIUMREST_QUESTION_ID_KEY = "'question_id' action parameter"
