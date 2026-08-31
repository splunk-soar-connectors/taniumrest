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
from dataclasses import dataclass
from time import sleep
from typing import Any

from soar_sdk.exceptions import ActionFailure

from ..constants import (
    endpoint_action,
    endpoint_action_result_data,
    endpoint_saved_action,
)
from ..tanium_client import TaniumClient
from ..utils import get_response_data

_WAIT_SECONDS = 5
_ACTION_POLL_MAX_SECONDS = 300

_COMPLETED_STATUSES = frozenset({"Completed", "Verified", "Succeeded"})
_FAILED_STATUSES = frozenset({"Expired", "Stopped", "NotSucceeded", "Failed"})
_RUNNING_STATUSES = frozenset(
    {"PendingVerification", "Copying", "Waiting", "Downloading", "Running"}
)


@dataclass
class ActionPollResult:
    """Structured result returned by poll_action_completion."""

    message: str
    saved_action_id: int | None = None
    action_id: int | None = None
    action_status: str | None = None
    pending_approval: bool = False
    completed_endpoint_count: int = 0
    failed_endpoint_count: int = 0
    running_endpoint_count: int = 0
    unknown_endpoint_count: int = 0
    expected_endpoint_count: int = 0
    # Set to True when the action ended in an error (pending approval, hard failure, timeout).
    # The caller can surface partial summary data even on failure paths.
    error: bool = False
    error_message: str = ""


def _fail(result: ActionPollResult, message: str) -> ActionPollResult:
    result.error = True
    result.error_message = message
    return result


def _parse_action_status(raw: str | None) -> str | None:
    """Normalize Tanium endpoint status values before classification."""
    if not raw:
        return None
    status = raw.split(":", 1)[-1] if ":" in raw else raw
    return status.strip().rstrip(".").replace(" ", "")


def _get_action_result_counts(response: dict[str, Any]) -> dict[str, int]:
    counts: dict[str, int] = {
        "completed": 0,
        "failed": 0,
        "running": 0,
        "unknown": 0,
        "expected": 0,
    }

    for result_set in (response.get("data") or {}).get("result_sets") or []:
        columns = result_set.get("columns") or []
        status_index = next(
            (
                i
                for i, col in enumerate(columns)
                if col.get("name") == "Action Statuses"
            ),
            None,
        )
        if status_index is None:
            continue

        try:
            expected = int(result_set.get("estimated_total") or 0)
        except (TypeError, ValueError):
            expected = 0
        counts["expected"] = max(counts["expected"], expected)

        for row in result_set.get("rows") or []:
            row_data = row.get("data") or []
            if status_index >= len(row_data):
                counts["unknown"] += 1
                continue
            status_values = row_data[status_index]
            if not isinstance(status_values, list):
                status_values = [status_values]
            raw_status = next(
                (
                    v.get("text")
                    for v in status_values
                    if isinstance(v, dict) and v.get("text")
                ),
                None,
            )
            status = _parse_action_status(raw_status)
            if status in _COMPLETED_STATUSES:
                counts["completed"] += 1
            elif status in _FAILED_STATUSES:
                counts["failed"] += 1
            elif status in _RUNNING_STATUSES:
                counts["running"] += 1
            else:
                counts["unknown"] += 1

    return counts


def poll_action_completion(
    client: TaniumClient, saved_action: dict[str, Any], expire_seconds: int
) -> ActionPollResult:
    """Poll until all targeted endpoints complete the action or timeout/error.

    Returns an ActionPollResult with structured summary data. Expected Tanium
    terminal states are returned with error=True so callers can surface partial
    summary data on failure paths.
    """
    result = ActionPollResult(message="")
    result.saved_action_id = saved_action.get("id")
    if not result.saved_action_id:
        return _fail(
            result,
            "Tanium did not return an ID for the created saved action",
        )

    if not saved_action.get("approved_flag"):
        result.pending_approval = True
        return _fail(
            result,
            f"Saved action {result.saved_action_id} is pending approval in Tanium "
            "and has not been issued to any endpoint",
        )

    action_id: int | None = (saved_action.get("last_action") or {}).get("id")
    max_wait = min(expire_seconds, _ACTION_POLL_MAX_SECONDS)
    elapsed = 0

    while elapsed <= max_wait:
        if action_id is None:
            try:
                sa_response = client.request(
                    "GET", endpoint_saved_action(result.saved_action_id)
                )
            except ActionFailure as e:
                return _fail(result, str(e))
            try:
                current = get_response_data(sa_response.get("data"), "saved action")
            except ActionFailure as e:
                return _fail(result, str(e))
            if not current.get("approved_flag"):
                result.pending_approval = True
                return _fail(
                    result,
                    f"Saved action {result.saved_action_id} is pending approval in Tanium "
                    "and has not been issued to any endpoint",
                )
            action_id = (current.get("last_action") or {}).get("id")

        if action_id is not None:
            result.action_id = action_id
            try:
                action_response = client.request("GET", endpoint_action(action_id))
            except ActionFailure as e:
                return _fail(result, str(e))
            try:
                action_data = get_response_data(action_response.get("data"), "action")
            except ActionFailure as e:
                return _fail(result, str(e))

            action_status = str(action_data.get("status") or "").lower()
            result.action_status = action_status
            if action_status in {"stopped", "expired"}:
                return _fail(
                    result, f"Action {action_id} ended with status '{action_status}'"
                )

            try:
                result_response = client.request(
                    "GET", endpoint_action_result_data(action_id)
                )
            except ActionFailure as e:
                return _fail(result, str(e))
            counts = _get_action_result_counts(result_response)
            result.completed_endpoint_count = counts["completed"]
            result.failed_endpoint_count = counts["failed"]
            result.running_endpoint_count = counts["running"]
            result.unknown_endpoint_count = counts["unknown"]
            result.expected_endpoint_count = counts["expected"]

            if counts["failed"] or counts["unknown"]:
                return _fail(
                    result,
                    f"Action {action_id} returned {counts['failed']} failed and "
                    f"{counts['unknown']} unknown endpoint results",
                )
            if (
                counts["expected"] > 0
                and counts["completed"] == counts["expected"]
                and counts["running"] == 0
            ):
                msg = f"Successfully completed action {action_id} on {counts['completed']} endpoints"
                result.message = msg
                return result

            if action_status and action_status not in {
                "active",
                "open",
                "pending",
                "closed",
            }:
                return _fail(
                    result,
                    f"Action {action_id} entered unexpected status '{action_status}' "
                    "before all endpoints completed",
                )

        if elapsed >= max_wait:
            break
        sleep(_WAIT_SECONDS)
        elapsed += _WAIT_SECONDS

    if action_id is None:
        return _fail(
            result,
            f"Saved action {result.saved_action_id} did not issue a child action "
            f"within {max_wait} seconds",
        )

    return _fail(
        result,
        f"Action {action_id} did not explicitly complete on all expected endpoints "
        f"within {max_wait} seconds",
    )
