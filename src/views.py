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
import os

from jinja2 import Environment, FileSystemLoader, select_autoescape

_TEMPLATES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "templates")


def _get_renderer():
    env = Environment(
        loader=FileSystemLoader(_TEMPLATES_DIR),
        trim_blocks=True,
        lstrip_blocks=True,
        autoescape=select_autoescape(["html"]),
    )
    return env


def _extract_result_sets(all_app_runs):
    for _summary, action_results in all_app_runs:
        for ar in action_results:
            for record in ar.get_data():
                result_sets = record.get("result_sets") or record.get("data", {}).get("result_sets")
                if result_sets:
                    return result_sets
    return []


def _extract_action_record(all_app_runs):
    for _summary, action_results in all_app_runs:
        for ar in action_results:
            for record in ar.get_data():
                return record
    return {}


def run_query_view(provides, all_app_runs, context) -> str:
    context["prerender"] = True
    env = _get_renderer()
    tmpl = env.get_template("taniumrest_run_query.html")
    return tmpl.render(title="Run Query Results", result_sets=_extract_result_sets(all_app_runs))


def list_processes_view(provides, all_app_runs, context) -> str:
    context["prerender"] = True
    env = _get_renderer()
    tmpl = env.get_template("taniumrest_run_query.html")
    return tmpl.render(title="List Processes Results", result_sets=_extract_result_sets(all_app_runs))


def get_question_results_view(provides, all_app_runs, context) -> str:
    context["prerender"] = True
    env = _get_renderer()
    tmpl = env.get_template("taniumrest_get_question_results.html")
    return tmpl.render(title="Question Results", result_sets=_extract_result_sets(all_app_runs))


def execute_action_view(provides, all_app_runs, context) -> str:
    context["prerender"] = True
    record = _extract_action_record(all_app_runs)
    pkg = record.get("package_spec") or {}
    rows = [{
        "STATUS": "success" if record else "unknown",
        "ACTION ID": str(record.get("id", "")),
        "NAME": str(record.get("name", "")),
        "EXPIRE SECONDS": str(record.get("expire_seconds", "")),
        "START TIME": str(record.get("start_time", "")),
        "ISSUE SECONDS": str(record.get("issue_seconds", "")),
        "DISTRIBUTE SECONDS": str(record.get("distribute_seconds", "")),
        "END TIME": str(record.get("end_time", "")),
        "PACKAGE ID": str(pkg.get("id", "")),
        "PACKAGE NAME": str(pkg.get("name", "")),
    }] if record else []
    env = _get_renderer()
    tmpl = env.get_template("taniumrest_action.html")
    return tmpl.render(title="Execute Action", rows=rows)


def parse_question_view(provides, all_app_runs, context) -> str:
    context["prerender"] = True
    rows = []
    for _summary, action_results in all_app_runs:
        for ar in action_results:
            for record in ar.get_data():
                question_text = record.get("question_text", "")
                if question_text:
                    rows.append({"PARSED QUESTION": question_text})
    env = _get_renderer()
    tmpl = env.get_template("taniumrest_parse_question.html")
    return tmpl.render(title="Parse Question Results", rows=rows)


def terminate_process_view(provides, all_app_runs, context) -> str:
    context["prerender"] = True
    record = _extract_action_record(all_app_runs)
    pkg = record.get("package_spec") or {}
    rows = [{
        "STATUS": "success" if record else "unknown",
        "ACTION ID": str(record.get("id", "")),
        "NAME": str(record.get("name", "")),
        "EXPIRE SECONDS": str(record.get("expire_seconds", "")),
        "START TIME": str(record.get("start_time", "")),
        "ISSUE SECONDS": str(record.get("issue_seconds", "")),
        "DISTRIBUTE SECONDS": str(record.get("distribute_seconds", "")),
        "END TIME": str(record.get("end_time", "")),
        "PACKAGE ID": str(pkg.get("id", "")),
        "PACKAGE NAME": str(pkg.get("name", "")),
    }] if record else []
    env = _get_renderer()
    tmpl = env.get_template("taniumrest_action.html")
    return tmpl.render(title="Terminate Process", rows=rows)
