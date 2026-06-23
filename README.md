# Tanium REST

Publisher: Splunk <br>
Connector Version: 2.5.0 <br>
Product Vendor: Tanium <br>
Product Name: Tanium REST <br>
Minimum Product Version: 7.0.0

This app supports investigative and generic actions on Tanium

### Configuration variables

This table lists the configuration variables required to operate Tanium REST. These variables are specified when configuring a Tanium REST asset in Splunk SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**base_url** | required | string | Base URL (e.g. https://taniumserver) |
**api_token** | optional | password | API Token |
**username** | optional | string | Username |
**password** | optional | password | Password |
**verify_server_cert** | optional | boolean | Verify Server Certificate |
**results_percentage** | optional | numeric | Consider question results complete at (% out of 100) |
**integration_header_value** | optional | string | Optional value for the x-tanium-integration API header. Configure only when required by Tanium partner or test accounts. |

### Supported Actions

[test connectivity](#action-test-connectivity) - test connectivity <br>
[list processes](#action-list-processes) - List the running processes of the devices registered on the Tanium server <br>
[parse question](#action-parse-question) - Parses the supplied text into a valid Tanium query string <br>
[list questions](#action-list-questions) - Retrieves either a history of the most recent questions or a list of saved questions <br>
[terminate process](#action-terminate-process) - Kill a running process of the devices registered on the Tanium server <br>
[execute action](#action-execute-action) - Execute an action on the Tanium server <br>
[run query](#action-run-query) - Run a search query on the devices registered on the Tanium server <br>
[create group](#action-create-group) - Create a Tanium manual computer group from hostnames and IP addresses <br>
[find groups](#action-find-groups) - Find Tanium manual computer groups matching hostnames or IP addresses <br>
[delete group](#action-delete-group) - Delete a Tanium manual computer group by ID <br>
[get question results](#action-get-question-results) - Return the results for an already asked question <br>
[make request](#action-make-request) - Make a generic HTTP request to the Tanium REST API.

## action: 'test connectivity'

test connectivity

Type: **test** <br>
Read only: **True**

Basic test for app.

#### Action Parameters

No parameters are required for this action

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list processes'

List the running processes of the devices registered on the Tanium server

Type: **investigate** <br>
Read only: **True**

This action requires specifying a sensor to be used to list processes. A standard Tanium sensor, 'Process Details' is used by default but a different sensor can be specified instead. Note that the 'Process Details' sensor may not be available on all Tanium deployments. Note that at this time this action only supports limiting the query to specified computer groups, but a generic Run Query action can be constructed to query an in individual computer's processes. As pagination is not implemented, the result(s) of the action will be the result(s) that are fetched in a single API call.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**sensor** | required | Sensor which will list all the processes | string | |
**group_name** | optional | Computer group name of which the processes will be listed | string | |
**timeout_seconds** | required | The number of seconds before the question expires | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.sensor | string | | |
action_result.parameter.group_name | string | | |
action_result.parameter.timeout_seconds | numeric | | |
action_result.data.\*.data.max_available_age | string | | |
action_result.data.\*.data.now | string | | 2019/07/24 11:43:42 GMT-0000 |
action_result.data.\*.data.result_sets.\*.age | numeric | | 0 |
action_result.data.\*.data.result_sets.\*.archived_question_id | numeric | `taniumrest question id` | 0 |
action_result.data.\*.data.result_sets.\*.cache_id | string | | 12418149 |
action_result.data.\*.data.result_sets.\*.columns.\*.hash | numeric | | 3744593586 |
action_result.data.\*.data.result_sets.\*.columns.\*.name | string | | Process |
action_result.data.\*.data.result_sets.\*.columns.\*.type | numeric | | 1 |
action_result.data.\*.data.result_sets.\*.error_count | numeric | | 0 |
action_result.data.\*.data.result_sets.\*.estimated_total | numeric | | 2 |
action_result.data.\*.data.result_sets.\*.expiration | numeric | | 0 |
action_result.data.\*.data.result_sets.\*.expire_seconds | numeric | | 0 |
action_result.data.\*.data.result_sets.\*.filtered_row_count | numeric | | 35 |
action_result.data.\*.data.result_sets.\*.filtered_row_count_machines | numeric | | 53 |
action_result.data.\*.data.result_sets.\*.id | numeric | `taniumrest question id` | 58456 |
action_result.data.\*.data.result_sets.\*.issue_seconds | numeric | | 0 |
action_result.data.\*.data.result_sets.\*.item_count | numeric | | 35 |
action_result.data.\*.data.result_sets.\*.mr_passed | numeric | | 2 |
action_result.data.\*.data.result_sets.\*.mr_tested | numeric | | 2 |
action_result.data.\*.data.result_sets.\*.no_results_count | numeric | | 0 |
action_result.data.\*.data.result_sets.\*.passed | numeric | | 2 |
action_result.data.\*.data.result_sets.\*.question_id | numeric | `taniumrest question id` | 58456 |
action_result.data.\*.data.result_sets.\*.report_count | numeric | | 2 |
action_result.data.\*.data.result_sets.\*.row_count | numeric | | 35 |
action_result.data.\*.data.result_sets.\*.row_count_machines | numeric | | 53 |
action_result.data.\*.data.result_sets.\*.rows.\*.cid | numeric | | 0 |
action_result.data.\*.data.result_sets.\*.rows.\*.data.\*.text | string | | explorer.exe |
action_result.data.\*.data.result_sets.\*.rows.\*.id | numeric | | 58783672 |
action_result.data.\*.data.result_sets.\*.saved_question_id | numeric | | 0 |
action_result.data.\*.data.result_sets.\*.seconds_since_issued | numeric | | 0 |
action_result.data.\*.data.result_sets.\*.select_count | numeric | | 1 |
action_result.data.\*.data.result_sets.\*.tested | numeric | | 2 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'parse question'

Parses the supplied text into a valid Tanium query string

Type: **investigate** <br>
Read only: **True**

<p>When asked a non-saved question in the <b>query_text</b> parameter, it will parse the given query and give a list of suggestions that are related to it.</p><p>For example, on the Tanium platform, if one were to just ask the question, 'all IP addresses,' Tanium will give the suggestions:<br><ul><li>Get Static IP Addresses from all machines</li><li>Get IP Routes from all machines</li><li>Get IP Address from all machines</li><li>Get IP Connections from all machines</li><li>Get IP Route Details from all machines</li><li>Get Network IP Gateway from all machines</li></ul><br>Tanium sorts this list, from most-related to least-related.</p>

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**query_text** | required | Query text to parse | string | `taniumrest question text` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.query_text | string | `taniumrest question text` | |
action_result.data.\*.expire_seconds | numeric | | 600 |
action_result.data.\*.force_computer_id_flag | numeric | | |
action_result.data.\*.from_canonical_text | numeric | | 0 |
action_result.data.\*.group | string | `taniumrest group definition` | { group id object } |
action_result.data.\*.question_text | string | `taniumrest question text` | Get Child Processes from all machines |
action_result.data.\*.score | numeric | | 7082 |
action_result.data.\*.selects.\*.filter.all_values_flag | boolean | | True False |
action_result.data.\*.selects.\*.filter.delimiter | string | | |
action_result.data.\*.selects.\*.filter.delimiter_index | numeric | | |
action_result.data.\*.selects.\*.filter.ignore_case_flag | boolean | | True False |
action_result.data.\*.selects.\*.filter.max_age_seconds | numeric | | |
action_result.data.\*.selects.\*.filter.not_flag | boolean | | True False |
action_result.data.\*.selects.\*.filter.operator | string | | RegexMatch |
action_result.data.\*.selects.\*.filter.substring_flag | boolean | | True False |
action_result.data.\*.selects.\*.filter.substring_length | numeric | | |
action_result.data.\*.selects.\*.filter.substring_start | numeric | | |
action_result.data.\*.selects.\*.filter.value | string | | |
action_result.data.\*.selects.\*.filter.value_type | string | | String |
action_result.data.\*.selects.\*.sensor.delimiter | string | | , |
action_result.data.\*.selects.\*.sensor.hash | numeric | | 3867657808 |
action_result.data.\*.selects.\*.sensor.id | numeric | | 350 |
action_result.data.\*.selects.\*.sensor.max_age_seconds | numeric | | 86400 |
action_result.data.\*.selects.\*.sensor.name | string | | Child Processes |
action_result.data.\*.selects.\*.sensor.parameter_definition | string | | |
action_result.data.\*.selects.\*.sensor.value_type | string | | String |
action_result.data.\*.sensor_references.\*.name | string | | Child Processes |
action_result.data.\*.sensor_references.\*.real_ms_avg | numeric | | 0 |
action_result.data.\*.sensor_references.\*.start_char | numeric | | 4 |
action_result.data.\*.skip_lock_flag | numeric | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list questions'

Retrieves either a history of the most recent questions or a list of saved questions

Type: **investigate** <br>
Read only: **True**

If the <b>list_saved_questions</b> parameter is true, this action will return a list of saved questions. If the flag is not set, this action will return the history of recently asked questions. As pagination is not implemented, the result(s) of the action will be the result(s) that are fetched in a single API call.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**list_saved_questions** | optional | Retrieve Saved Questions | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.list_saved_questions | boolean | | |
action_result.data.\*.action_tracking_flag | boolean | | True False |
action_result.data.\*.archive_enabled_flag | boolean | | True False |
action_result.data.\*.archive_owner.id | numeric | | 1 |
action_result.data.\*.archive_owner.name | string | | administrator |
action_result.data.\*.content_set.id | numeric | | 7 |
action_result.data.\*.content_set.name | string | | Detect Service |
action_result.data.\*.context_group.id | numeric | | |
action_result.data.\*.expiration | string | | 2001-01-01T00:00:00Z |
action_result.data.\*.expire_seconds | numeric | | 600 |
action_result.data.\*.hidden_flag | boolean | | True False |
action_result.data.\*.id | numeric | `taniumrest question id` | 26 |
action_result.data.\*.is_expired | boolean | | True False |
action_result.data.\*.issue_seconds | numeric | | 300 |
action_result.data.\*.issue_seconds_never_flag | boolean | | True False |
action_result.data.\*.keep_seconds | numeric | | 0 |
action_result.data.\*.management_rights_group.id | numeric | | |
action_result.data.\*.metadata.\*.admin_flag | boolean | | True False |
action_result.data.\*.metadata.\*.name | string | | SQPreference_Default |
action_result.data.\*.metadata.\*.value | string | | {"default_grid_zoom_level":0,"default_line_zoom_level":12,"default_tab":1,"merge_flag":0,"drilldown_flag":0} |
action_result.data.\*.mod_time | string | | 2019-02-11T21:22:25Z |
action_result.data.\*.mod_user.display_name | string | | |
action_result.data.\*.mod_user.domain | string | `domain` | |
action_result.data.\*.mod_user.id | numeric | | 1 |
action_result.data.\*.mod_user.name | string | | administrator |
action_result.data.\*.most_recent_question_id | numeric | `taniumrest question id` | 56071 |
action_result.data.\*.name | string | | Detect Managed Unix Endpoints |
action_result.data.\*.packages.\*.id | numeric | | 1 |
action_result.data.\*.packages.\*.name | string | | Distribute Tanium Standard Utilities |
action_result.data.\*.public_flag | boolean | | True False |
action_result.data.\*.query_text | string | `taniumrest question text` | Get Detect Tools Status from all machines with ( Detect Tools Status contains engine version and Detect Tools Status contains Unix ) |
action_result.data.\*.question.id | numeric | `taniumrest question id` | 56071 |
action_result.data.\*.row_count_flag | boolean | | True False |
action_result.data.\*.saved_question.id | numeric | | 15 |
action_result.data.\*.skip_lock_flag | boolean | | True False |
action_result.data.\*.sort_column | numeric | | 0 |
action_result.data.\*.user.deleted_flag | boolean | | True False |
action_result.data.\*.user.id | numeric | | 1 |
action_result.data.\*.user.name | string | | administrator |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'terminate process'

Kill a running process of the devices registered on the Tanium server

Type: **generic** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**action_name** | required | Name of the action | string | |
**action_group** | required | Group of the action | string | |
**package_name** | required | Package name that will be executed | string | |
**package_parameters** | optional | Package parameters of the corresponding package | string | |
**group_name** | optional | Computer group name of which the process will be terminated | string | |
**distribute_seconds** | optional | The number of seconds over which to deploy the action | numeric | |
**issue_seconds** | optional | The number of seconds to reissue an action from the saved action | numeric | |
**expire_seconds** | required | The duration from the start time before the action expires | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.action_name | string | | |
action_result.parameter.action_group | string | | |
action_result.parameter.package_name | string | | |
action_result.parameter.package_parameters | string | | |
action_result.parameter.group_name | string | | |
action_result.parameter.distribute_seconds | numeric | | |
action_result.parameter.issue_seconds | numeric | | |
action_result.parameter.expire_seconds | numeric | | |
action_result.data.\*.action_group_id | numeric | | 151 |
action_result.data.\*.approved_flag | boolean | | True False |
action_result.data.\*.approver.id | numeric | | 1 |
action_result.data.\*.approver.name | string | | administrator |
action_result.data.\*.comment | string | | |
action_result.data.\*.creation_time | string | | 2019-09-18T04:53:58Z |
action_result.data.\*.distribute_seconds | numeric | | 0 |
action_result.data.\*.end_time | string | | Never |
action_result.data.\*.expire_seconds | numeric | | 600 |
action_result.data.\*.id | numeric | | 523 |
action_result.data.\*.issue_count | numeric | | 0 |
action_result.data.\*.issue_seconds | numeric | | 0 |
action_result.data.\*.last_action.id | numeric | | 272936 |
action_result.data.\*.last_action.start_time | string | | Never |
action_result.data.\*.last_action.target_group.id | numeric | | 3646 |
action_result.data.\*.last_start_time | string | | Never |
action_result.data.\*.name | string | | test terminate process |
action_result.data.\*.next_start_time | string | | Never |
action_result.data.\*.package_spec.available_time | string | | 2001-01-01T00:00:00Z |
action_result.data.\*.package_spec.command | string | | cmd /c mkdir C:\\Users\\Administrator\\some_dir\\ |
action_result.data.\*.package_spec.command_timeout | numeric | | 600 |
action_result.data.\*.package_spec.content_set.id | numeric | | 9 |
action_result.data.\*.package_spec.content_set.name | string | | |
action_result.data.\*.package_spec.creation_time | string | | 2001-01-01T00:00:00Z |
action_result.data.\*.package_spec.deleted_flag | boolean | | True False |
action_result.data.\*.package_spec.display_name | string | | |
action_result.data.\*.package_spec.expire_seconds | numeric | | 3600 |
action_result.data.\*.package_spec.files.\*.bytes_downloaded | numeric | | |
action_result.data.\*.package_spec.files.\*.bytes_total | numeric | | 39221 |
action_result.data.\*.package_spec.files.\*.cache_status | string | | Cached |
action_result.data.\*.package_spec.files.\*.download_seconds | numeric | | |
action_result.data.\*.package_spec.files.\*.download_start_time | string | | 2021-11-16T18:53:31Z |
action_result.data.\*.package_spec.files.\*.hash | string | | b6c7534b828ff6e28f1467041a6f6f9a5ad7a7f4ac367c5425f16e249c77ec30 |
action_result.data.\*.package_spec.files.\*.id | numeric | | 73 |
action_result.data.\*.package_spec.files.\*.last_download_progress_time | string | | 2021-11-16T18:53:31Z |
action_result.data.\*.package_spec.files.\*.name | string | | clean-stale-tanium-client-data.vbs |
action_result.data.\*.package_spec.files.\*.size | numeric | | 39221 |
action_result.data.\*.package_spec.files.\*.source | string | | |
action_result.data.\*.package_spec.files.\*.status | numeric | | 200 |
action_result.data.\*.package_spec.hidden_flag | boolean | | True False |
action_result.data.\*.package_spec.id | numeric | | 600 |
action_result.data.\*.package_spec.last_modified_by | string | | |
action_result.data.\*.package_spec.last_update | string | | 2019-09-18T04:53:58Z |
action_result.data.\*.package_spec.mod_user.display_name | string | | |
action_result.data.\*.package_spec.mod_user.domain | string | `domain` | |
action_result.data.\*.package_spec.mod_user.id | numeric | | 0 |
action_result.data.\*.package_spec.mod_user.name | string | | |
action_result.data.\*.package_spec.modification_time | string | | 2001-01-01T00:00:00Z |
action_result.data.\*.package_spec.name | string | | terminate process |
action_result.data.\*.package_spec.process_group_flag | boolean | | True False |
action_result.data.\*.package_spec.skip_lock_flag | boolean | | True False |
action_result.data.\*.package_spec.source_hash | string | `sha256` | b75af868db6d80c0e603ce8827146e2e44f2728c6ae98fd6082003412cf3a207 |
action_result.data.\*.package_spec.source_hash_changed_flag | boolean | | True False |
action_result.data.\*.package_spec.source_id | numeric | | 221 |
action_result.data.\*.package_spec.verify_expire_seconds | numeric | | 3600 |
action_result.data.\*.package_spec.verify_group.id | numeric | | 0 |
action_result.data.\*.package_spec.verify_group_id | numeric | | 0 |
action_result.data.\*.policy_flag | boolean | | True False |
action_result.data.\*.public_flag | boolean | | True False |
action_result.data.\*.start_now_flag | boolean | | True False |
action_result.data.\*.start_time | string | | 2019-09-18T04:53:58Z |
action_result.data.\*.status | numeric | | 0 |
action_result.data.\*.target_group.id | numeric | | 3646 |
action_result.data.\*.user.id | numeric | | 1 |
action_result.data.\*.user.name | string | | administrator |
action_result.data.\*.user_start_time | string | | 2001-01-01T00:00:00Z |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'execute action'

Execute an action on the Tanium server

Type: **generic** <br>
Read only: **False**

<li>See top-level app documentation for example parameters.</li><li>If a parameterized package is used for executing an action all the parameters must be provided with correct and unique keys. If any key is repeated then the value of that key will be overwritten.</li><li>If the <b>issue_seconds</b> parameter is provided, then the action will respawn after a time interval provided in the <b>issue_seconds</b> parameter.</li>

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**action_name** | required | Creates a name for the action executed | string | |
**action_group** | required | Group of the action | string | |
**package_name** | required | Name of the Tanium package to be executed | string | |
**package_parameters** | optional | Parameter inputs of the corresponding package. Provide JSON format (i.e. {"$1": "Standard_Collection", "$2": "SCP"}) | string | |
**group_name** | optional | The Tanium Computer Group name on which the action will be executed. If left blank, will execute on all registered IP addresses/hostnames in your Tanium instance | string | `taniumrest group definition` |
**distribute_seconds** | optional | The number of seconds over which to deploy the action | numeric | |
**issue_seconds** | optional | The number of seconds to reissue an action from the saved action | numeric | |
**expire_seconds** | required | The duration from the start time before the action expires | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.action_name | string | | |
action_result.parameter.action_group | string | | |
action_result.parameter.package_name | string | | |
action_result.parameter.package_parameters | string | | |
action_result.parameter.group_name | string | `taniumrest group definition` | |
action_result.parameter.distribute_seconds | numeric | | |
action_result.parameter.issue_seconds | numeric | | |
action_result.parameter.expire_seconds | numeric | | |
action_result.data.\*.action_group_id | numeric | | 151 |
action_result.data.\*.approved_flag | boolean | | True False |
action_result.data.\*.approver.id | numeric | | 1 |
action_result.data.\*.approver.name | string | | administrator |
action_result.data.\*.comment | string | | |
action_result.data.\*.creation_time | string | | 2019-09-16T07:43:57Z |
action_result.data.\*.distribute_seconds | numeric | | 0 |
action_result.data.\*.end_time | string | | Never |
action_result.data.\*.expire_seconds | numeric | | 600 |
action_result.data.\*.id | numeric | `taniumrest question id` | 482 |
action_result.data.\*.issue_count | numeric | | 0 |
action_result.data.\*.issue_seconds | numeric | | 0 |
action_result.data.\*.last_action.id | numeric | | 272568 |
action_result.data.\*.last_action.start_time | string | | Never |
action_result.data.\*.last_action.target_group.id | numeric | | 3614 |
action_result.data.\*.last_start_time | string | | Never |
action_result.data.\*.name | string | | test action start 7 |
action_result.data.\*.next_start_time | string | | Never |
action_result.data.\*.package_spec.available_time | string | | 2001-01-01T00:00:00Z |
action_result.data.\*.package_spec.command | string | | cmd /c mkdir C:\\Users\\Administrator\\test123\\"TestDirectory" |
action_result.data.\*.package_spec.command_timeout | numeric | | 600 |
action_result.data.\*.package_spec.content_set.id | numeric | | 2 |
action_result.data.\*.package_spec.content_set.name | string | | |
action_result.data.\*.package_spec.creation_time | string | | 2001-01-01T00:00:00Z |
action_result.data.\*.package_spec.deleted_flag | boolean | | True False |
action_result.data.\*.package_spec.display_name | string | | |
action_result.data.\*.package_spec.expire_seconds | numeric | | 3600 |
action_result.data.\*.package_spec.files.\*.bytes_downloaded | numeric | | |
action_result.data.\*.package_spec.files.\*.bytes_total | numeric | | 39221 |
action_result.data.\*.package_spec.files.\*.cache_status | string | | Cached |
action_result.data.\*.package_spec.files.\*.download_seconds | numeric | | |
action_result.data.\*.package_spec.files.\*.download_start_time | string | | 2021-11-16T18:53:31Z |
action_result.data.\*.package_spec.files.\*.hash | string | | b6c7534b828ff6e28f1467041a6f6f9a5ad7a7f4ac367c5425f16e249c77ec30 |
action_result.data.\*.package_spec.files.\*.id | numeric | | 73 |
action_result.data.\*.package_spec.files.\*.last_download_progress_time | string | | 2021-11-16T18:53:31Z |
action_result.data.\*.package_spec.files.\*.name | string | | clean-stale-tanium-client-data.vbs |
action_result.data.\*.package_spec.files.\*.size | numeric | | 39221 |
action_result.data.\*.package_spec.files.\*.source | string | | |
action_result.data.\*.package_spec.files.\*.status | numeric | | 200 |
action_result.data.\*.package_spec.hidden_flag | boolean | | True False |
action_result.data.\*.package_spec.id | numeric | | 559 |
action_result.data.\*.package_spec.last_modified_by | string | | |
action_result.data.\*.package_spec.last_update | string | | 2019-09-16T07:43:57Z |
action_result.data.\*.package_spec.mod_user.display_name | string | | |
action_result.data.\*.package_spec.mod_user.domain | string | `domain` | |
action_result.data.\*.package_spec.mod_user.id | numeric | | 0 |
action_result.data.\*.package_spec.mod_user.name | string | | |
action_result.data.\*.package_spec.modification_time | string | | 2001-01-01T00:00:00Z |
action_result.data.\*.package_spec.name | string | | make directory |
action_result.data.\*.package_spec.parameter_definition | string | | |
action_result.data.\*.package_spec.parameters.\*.key | string | | $1 |
action_result.data.\*.package_spec.parameters.\*.type | numeric | | 0 |
action_result.data.\*.package_spec.parameters.\*.value | string | | TestDirectory |
action_result.data.\*.package_spec.process_group_flag | boolean | | True False |
action_result.data.\*.package_spec.skip_lock_flag | boolean | | True False |
action_result.data.\*.package_spec.source_hash | string | `sha256` | d36e609e026380ce117388858503384ecd50f8fb9321ccaeab9647b4131cc7a7 |
action_result.data.\*.package_spec.source_hash_changed_flag | boolean | | True False |
action_result.data.\*.package_spec.source_id | numeric | | 500 |
action_result.data.\*.package_spec.verify_expire_seconds | numeric | | 3600 |
action_result.data.\*.package_spec.verify_group.id | numeric | | 0 |
action_result.data.\*.package_spec.verify_group_id | numeric | | 0 |
action_result.data.\*.policy_flag | boolean | | True False |
action_result.data.\*.public_flag | boolean | | True False |
action_result.data.\*.start_now_flag | boolean | | True False |
action_result.data.\*.start_time | string | | 2019-09-16T07:43:57Z |
action_result.data.\*.status | numeric | | 0 |
action_result.data.\*.target_group.id | numeric | | 3614 |
action_result.data.\*.user.id | numeric | | 1 |
action_result.data.\*.user.name | string | | administrator |
action_result.data.\*.user_start_time | string | | 2001-01-01T00:00:00Z |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'run query'

Run a search query on the devices registered on the Tanium server

Type: **investigate** <br>
Read only: **True**

See top-level app documentation for example parameters. For manual questions only, the action waits for <b>timeout_seconds</b> provided by the user in intervals of 5 seconds to fetch the results. The action is a success as soon as the results are retrieved or else it will timeout and fail. As pagination is not implemented, the result(s) of the action will be the result(s) that are fetched in a single API call. If an endpoint takes longer than usual to evaluate a sensor, it might initially supply the answer[current results unavailable] to the answer message that it passes along the linear chain and ultimately to the Tanium Server. However, the sensor process continues on the endpoint after supplying that initial answer and, upon completing the process, the endpoint sends its updated answer. Reference Link: ~https://docs.tanium.com/interact/interact/results.html.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**query_text** | required | Query to run (in Tanium Question Syntax) | string | `taniumrest question text` |
**group_name** | optional | The Tanium Computer Group name on which the query will be executed (manual query only) | string | |
**is_saved_question** | optional | Check this box if the query text parameter refers to a 'Saved Question' on your Tanium | boolean | |
**timeout_seconds** | required | The number of seconds before the question expires (manual query only) | numeric | |
**wait_for_results_processing** | optional | Flag to wait for endpoint to return full results | boolean | |
**return_when_n_results_available** | optional | Return results as soon as 'n' answers are available | numeric | |
**wait_for_n_results_available** | optional | Wait until 'n' results are present, even if hit the percent complete threshold | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.query_text | string | `taniumrest question text` | |
action_result.parameter.group_name | string | | |
action_result.parameter.is_saved_question | boolean | | |
action_result.parameter.timeout_seconds | numeric | | |
action_result.parameter.wait_for_results_processing | boolean | | |
action_result.parameter.return_when_n_results_available | numeric | | |
action_result.parameter.wait_for_n_results_available | numeric | | |
action_result.data.\*.data.max_available_age | string | | |
action_result.data.\*.data.now | string | | 2019/07/24 07:53:06 GMT-0000 |
action_result.data.\*.data.result_sets.\*.age | numeric | | 0 |
action_result.data.\*.data.result_sets.\*.archived_question_id | numeric | | 0 |
action_result.data.\*.data.result_sets.\*.cache_id | string | | 2668614289 |
action_result.data.\*.data.result_sets.\*.columns.\*.hash | numeric | | 3112892791 |
action_result.data.\*.data.result_sets.\*.columns.\*.name | string | | DNS Server |
action_result.data.\*.data.result_sets.\*.columns.\*.type | numeric | | 5 |
action_result.data.\*.data.result_sets.\*.error_count | numeric | | 0 |
action_result.data.\*.data.result_sets.\*.estimated_total | numeric | | 2 |
action_result.data.\*.data.result_sets.\*.expiration | numeric | | 0 |
action_result.data.\*.data.result_sets.\*.expire_seconds | numeric | | 0 |
action_result.data.\*.data.result_sets.\*.filtered_row_count | numeric | | 1 |
action_result.data.\*.data.result_sets.\*.filtered_row_count_machines | numeric | | 1 |
action_result.data.\*.data.result_sets.\*.id | numeric | `taniumrest question id` | 58377 |
action_result.data.\*.data.result_sets.\*.issue_seconds | numeric | | 0 |
action_result.data.\*.data.result_sets.\*.item_count | numeric | | 1 |
action_result.data.\*.data.result_sets.\*.mr_passed | numeric | | 1 |
action_result.data.\*.data.result_sets.\*.mr_tested | numeric | | 2 |
action_result.data.\*.data.result_sets.\*.no_results_count | numeric | | 0 |
action_result.data.\*.data.result_sets.\*.passed | numeric | | 1 |
action_result.data.\*.data.result_sets.\*.question_id | numeric | `taniumrest question id` | 58377 |
action_result.data.\*.data.result_sets.\*.report_count | numeric | | 2 |
action_result.data.\*.data.result_sets.\*.row_count | numeric | | 1 |
action_result.data.\*.data.result_sets.\*.row_count_machines | numeric | | 1 |
action_result.data.\*.data.result_sets.\*.rows.\*.cid | numeric | | 0 |
action_result.data.\*.data.result_sets.\*.rows.\*.data.\*.text | string | | 192.168.1.1 |
action_result.data.\*.data.result_sets.\*.rows.\*.id | numeric | | 1306085003 |
action_result.data.\*.data.result_sets.\*.saved_question_id | numeric | | 0 |
action_result.data.\*.data.result_sets.\*.seconds_since_issued | numeric | | 0 |
action_result.data.\*.data.result_sets.\*.select_count | numeric | | 1 |
action_result.data.\*.data.result_sets.\*.tested | numeric | | 1 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'create group'

Create a Tanium manual computer group from hostnames and IP addresses

Type: **generic** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**group_name** | required | Name of the Tanium Computer Group to create | string | `taniumrest group name` |
**computer_names** | optional | Comma-separated hostnames or computer names to include in the group | string | `host name` |
**ip_addresses** | optional | Comma-separated IP addresses to include in the group | string | `ip` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.group_name | string | `taniumrest group name` | |
action_result.parameter.computer_names | string | `host name` | |
action_result.parameter.ip_addresses | string | `ip` | |
action_result.data.\*.id | numeric | `taniumrest group id` | 1234 |
action_result.data.\*.name | string | `taniumrest group name` | manual-group-1 |
action_result.data.\*.deleted_flag | boolean | | True False |
action_result.data.\*.filter_flag | boolean | | True False |
action_result.data.\*.management_rights_flag | boolean | | True False |
action_result.data.\*.computer_specs.\*.id | numeric | | 1234 |
action_result.data.\*.computer_specs.\*.computer_name | string | `host name` | host1 |
action_result.data.\*.computer_specs.\*.ip_address | string | `ip` | 10.20.30.40 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'find groups'

Find Tanium manual computer groups matching hostnames or IP addresses

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**computer_names** | optional | Comma-separated hostnames or computer names used to find matching groups | string | `host name` |
**ip_addresses** | optional | Comma-separated IP addresses used to find matching groups | string | `ip` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.computer_names | string | `host name` | |
action_result.parameter.ip_addresses | string | `ip` | |
action_result.data.\*.id | numeric | `taniumrest group id` | 1234 |
action_result.data.\*.name | string | `taniumrest group name` | manual-group-1 |
action_result.data.\*.deleted_flag | boolean | | True False |
action_result.data.\*.filter_flag | boolean | | True False |
action_result.data.\*.management_rights_flag | boolean | | True False |
action_result.data.\*.computer_specs.\*.id | numeric | | 1234 |
action_result.data.\*.computer_specs.\*.computer_name | string | `host name` | host1 |
action_result.data.\*.computer_specs.\*.ip_address | string | `ip` | 10.20.30.40 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'delete group'

Delete a Tanium manual computer group by ID

Type: **generic** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**group_id** | required | ID of the Tanium manual computer group to delete | numeric | `taniumrest group id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.group_id | numeric | `taniumrest group id` | |
action_result.data.\*.id | numeric | `taniumrest group id` | 1234 |
action_result.data.\*.deleted_flag | boolean | | True False |
action_result.data.\*.name | string | `taniumrest group name` | manual-group-1 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get question results'

Return the results for an already asked question

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**question_id** | required | The ID of the question | numeric | `taniumrest question id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.question_id | numeric | `taniumrest question id` | |
action_result.data.\*.data.max_available_age | string | | |
action_result.data.\*.data.now | string | | 2019/07/24 07:53:06 GMT-0000 |
action_result.data.\*.data.result_sets.\*.age | numeric | | 0 |
action_result.data.\*.data.result_sets.\*.archived_question_id | numeric | | 0 |
action_result.data.\*.data.result_sets.\*.cache_id | string | | 2668614289 |
action_result.data.\*.data.result_sets.\*.columns.\*.hash | numeric | | 3112892791 |
action_result.data.\*.data.result_sets.\*.columns.\*.name | string | | DNS Server |
action_result.data.\*.data.result_sets.\*.columns.\*.type | numeric | | 5 |
action_result.data.\*.data.result_sets.\*.error_count | numeric | | 0 |
action_result.data.\*.data.result_sets.\*.estimated_total | numeric | | 2 |
action_result.data.\*.data.result_sets.\*.expiration | numeric | | 0 |
action_result.data.\*.data.result_sets.\*.expire_seconds | numeric | | 0 |
action_result.data.\*.data.result_sets.\*.filtered_row_count | numeric | | 1 |
action_result.data.\*.data.result_sets.\*.filtered_row_count_machines | numeric | | 1 |
action_result.data.\*.data.result_sets.\*.id | numeric | `taniumrest question id` | 58377 |
action_result.data.\*.data.result_sets.\*.issue_seconds | numeric | | 0 |
action_result.data.\*.data.result_sets.\*.item_count | numeric | | 1 |
action_result.data.\*.data.result_sets.\*.mr_passed | numeric | | 1 |
action_result.data.\*.data.result_sets.\*.mr_tested | numeric | | 2 |
action_result.data.\*.data.result_sets.\*.no_results_count | numeric | | 0 |
action_result.data.\*.data.result_sets.\*.passed | numeric | | 1 |
action_result.data.\*.data.result_sets.\*.question_id | numeric | `taniumrest question id` | 58377 |
action_result.data.\*.data.result_sets.\*.report_count | numeric | | 2 |
action_result.data.\*.data.result_sets.\*.row_count | numeric | | 1 |
action_result.data.\*.data.result_sets.\*.row_count_machines | numeric | | 1 |
action_result.data.\*.data.result_sets.\*.rows.\*.cid | numeric | | 0 |
action_result.data.\*.data.result_sets.\*.rows.\*.data.\*.text | string | | 192.168.1.1 |
action_result.data.\*.data.result_sets.\*.rows.\*.id | numeric | | 1306085003 |
action_result.data.\*.data.result_sets.\*.saved_question_id | numeric | | 0 |
action_result.data.\*.data.result_sets.\*.seconds_since_issued | numeric | | 0 |
action_result.data.\*.data.result_sets.\*.select_count | numeric | | 1 |
action_result.data.\*.data.result_sets.\*.tested | numeric | | 1 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'make request'

Make a generic HTTP request to the Tanium REST API.

Type: **generic** <br>
Read only: **False**

'make request' action for the app. Used to handle arbitrary HTTP requests with the app's asset

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**http_method** | required | The HTTP method to use for the request. | string | |
**endpoint** | required | Tanium REST API endpoint, relative to the base URL. Example: '/api/v2/saved_questions' or '/api/v2/sensors/by-name/IP%20Address' | string | |
**headers** | optional | The headers to send with the request (JSON object). An example is {'Content-Type': 'application/json'} | string | |
**query_parameters** | optional | Parameters to append to the URL (JSON object or query string). An example is ?key=value&key2=value2 | string | |
**body** | optional | The body to send with the request (JSON object). An example is {'key': 'value', 'key2': 'value2'} | string | |
**timeout** | optional | The timeout for the request in seconds. | numeric | |
**verify_ssl** | optional | Whether to verify the SSL certificate. Default is False. | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.http_method | string | | |
action_result.parameter.endpoint | string | | |
action_result.parameter.headers | string | | |
action_result.parameter.query_parameters | string | | |
action_result.parameter.body | string | | |
action_result.parameter.timeout | numeric | | |
action_result.parameter.verify_ssl | boolean | | |
action_result.data.\*.status_code | numeric | | 200 404 500 |
action_result.data.\*.response_body | string | | {"key": "value"} |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

______________________________________________________________________

Auto-generated Splunk SOAR Connector documentation.

Copyright 2026 Splunk Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
