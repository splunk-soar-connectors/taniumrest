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
from soar_sdk.app import App

from .create_group import CreateGroupSummaryOutput, create_group
from .delete_group import DeleteGroupSummaryOutput, delete_group
from .execute_action import ExecuteActionSummaryOutput, execute_action
from .find_groups import FindGroupsSummaryOutput, find_groups
from .get_question_results import GetQuestionResultsSummaryOutput, get_question_results
from .list_processes import ListProcessesSummaryOutput, list_processes
from .list_questions import ListQuestionsSummaryOutput, list_questions
from .make_request import make_request
from .parse_question import ParseQuestionSummaryOutput, parse_question
from .run_query import RunQuerySummaryOutput, run_query
from .terminate_process import TerminateProcessSummaryOutput, terminate_process
from ..views import (
    get_question_results_view,
    list_processes_view,
    run_query_view,
)


def register_actions(app: App) -> App:
    app.make_request()(make_request)
    app.register_action(
        action=create_group,
        description="Create a Tanium manual computer group from hostnames and IP addresses",
        action_type="generic",
        read_only=False,
        render_as="table",
        summary_type=CreateGroupSummaryOutput,
    )
    app.register_action(
        action=delete_group,
        description="Delete a Tanium manual computer group by ID",
        action_type="generic",
        read_only=False,
        render_as="table",
        summary_type=DeleteGroupSummaryOutput,
    )
    app.register_action(
        action=execute_action,
        description="Execute an action on the Tanium server",
        action_type="generic",
        read_only=False,
        verbose="<li>See top-level app documentation for example parameters.</li><li>If a parameterized package is used for executing an action all the parameters must be provided with correct and unique keys. If any key is repeated then the value of that key will be overwritten.</li><li>If the <b>issue_seconds</b> parameter is provided, then the action will respawn after a time interval provided in the <b>issue_seconds</b> parameter.</li>",
        render_as="table",
        summary_type=ExecuteActionSummaryOutput,
    )
    app.register_action(
        action=find_groups,
        description="Find Tanium manual computer groups matching hostnames or IP addresses",
        action_type="investigate",
        render_as="table",
        summary_type=FindGroupsSummaryOutput,
    )
    app.register_action(
        action=get_question_results,
        description="Return the results for an already asked question",
        action_type="investigate",
        view_handler=get_question_results_view,
        view_template="taniumrest_get_question_results.html",
        summary_type=GetQuestionResultsSummaryOutput,
    )
    app.register_action(
        action=list_processes,
        description="List the running processes of the devices registered on the Tanium server",
        action_type="investigate",
        verbose="This action requires specifying a sensor to be used to list processes. A standard Tanium sensor, 'Process Details' is used by default but a different sensor can be specified instead. Note that the 'Process Details' sensor may not be available on all Tanium deployments. Note that at this time this action only supports limiting the query to specified computer groups, but a generic Run Query action can be constructed to query an in individual computer's processes. As pagination is not implemented, the result(s) of the action will be the result(s) that are fetched in a single API call.",
        view_handler=list_processes_view,
        view_template="taniumrest_run_query.html",
        summary_type=ListProcessesSummaryOutput,
    )
    app.register_action(
        action=list_questions,
        description="Retrieves either a history of the most recent questions or a list of saved questions",
        action_type="investigate",
        verbose="If the <b>list_saved_questions</b> parameter is true, this action will return a list of saved questions. If the flag is not set, this action will return the history of recently asked questions. As pagination is not implemented, the result(s) of the action will be the result(s) that are fetched in a single API call.",
        render_as="table",
        summary_type=ListQuestionsSummaryOutput,
    )
    app.register_action(
        action=parse_question,
        description="Parses the supplied text into a valid Tanium query string",
        action_type="investigate",
        verbose="<p>When asked a non-saved question in the <b>query_text</b> parameter, it will parse the given query and give a list of suggestions that are related to it.</p><p>For example, on the Tanium platform, if one were to just ask the question, 'all IP addresses,' Tanium will give the suggestions:<br><ul><li>Get Static IP Addresses from all machines</li><li>Get IP Routes from all machines</li><li>Get IP Address from all machines</li><li>Get IP Connections from all machines</li><li>Get IP Route Details from all machines</li><li>Get Network IP Gateway from all machines</li></ul><br>Tanium sorts this list, from most-related to least-related.</p>",
        render_as="table",
        summary_type=ParseQuestionSummaryOutput,
    )
    app.register_action(
        action=run_query,
        description="Run a search query on the devices registered on the Tanium server",
        action_type="investigate",
        verbose="See top-level app documentation for example parameters. For manual questions only, the action waits for <b>timeout_seconds</b> provided by the user in intervals of 5 seconds to fetch the results. The action is a success as soon as the results are retrieved or else it will timeout and fail. As pagination is not implemented, the result(s) of the action will be the result(s) that are fetched in a single API call. If an endpoint takes longer than usual to evaluate a sensor, it might initially supply the answer[current results unavailable] to the answer message that it passes along the linear chain and ultimately to the Tanium Server. However, the sensor process continues on the endpoint after supplying that initial answer and, upon completing the process, the endpoint sends its updated answer. Reference Link: ~https://docs.tanium.com/interact/interact/results.html.",
        view_handler=run_query_view,
        view_template="taniumrest_run_query.html",
        summary_type=RunQuerySummaryOutput,
    )
    app.register_action(
        action=terminate_process,
        description=(
            "Kill a running process of the devices registered on the Tanium server. "
            "Note: This action is retained for compatibility; the same operation can "
            "be performed using execute action, and terminate process will be "
            "deprecated in a future release."
        ),
        action_type="generic",
        read_only=False,
        render_as="table",
        summary_type=TerminateProcessSummaryOutput,
    )
    return app
