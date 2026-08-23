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
from typing import Any

from soar_sdk.models.view import ViewContext

from .utils import normalize_result_data
from .actions.get_question_results import GetQuestionResultsOutput
from .actions.list_processes import ListProcessesOutput
from .actions.run_query import RunQueryOutput


def _result_sets_context(title: str, context: ViewContext, outputs: list[Any]) -> dict:
    result_sets = []
    for output in outputs:
        data = getattr(output, "data", None)
        result_sets.extend(getattr(data, "result_sets", None) or [])

    return {
        "title": title,
        "result_sets": result_sets,
        "container": context.container,
    }


def run_query_view(context: ViewContext, outputs: list[RunQueryOutput]) -> dict:
    return _result_sets_context("Run Query Results", context, outputs)


def list_processes_view(
    context: ViewContext, outputs: list[ListProcessesOutput]
) -> dict:
    return _result_sets_context("List Processes Results", context, outputs)


def get_question_results_view(
    context: ViewContext, outputs: list[GetQuestionResultsOutput]
) -> dict:
    result_sets = []
    for output in outputs:
        normalized_output = normalize_result_data(output.model_dump())
        data = normalized_output.get("data", {})
        result_sets.extend(data.get("result_sets") or [])

    return {
        "title": "Question Results",
        "result_sets": result_sets,
        "container": context.container,
    }
