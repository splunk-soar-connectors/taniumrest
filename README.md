[comment]: # "Auto-generated SOAR connector documentation"
# Tanium REST

Publisher: Splunk  
Connector Version: 2.2.1  
Product Vendor: Tanium  
Product Name: Tanium REST  
Product Version Supported (regex): ".\*"  
Minimum Product Version: 5.3.3  

This app supports investigative and generic actions on Tanium

[comment]: # " File: README.md"
[comment]: # "  Copyright (c) 2019-2024 Splunk Inc."
[comment]: # "  Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "  you may not use this file except in compliance with the License."
[comment]: # "  You may obtain a copy of the License at"
[comment]: # ""
[comment]: # "      http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # ""
[comment]: # "  Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "  the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "  either express or implied. See the License for the specific language governing permissions"
[comment]: # "  and limitations under the License."
[comment]: # ""
[comment]: # " pragma: allowlist secret "
## Playbook Backward Compatibility

-   The existing action parameters have been modified for the action given below. Hence, it is
    requested to the end-user to please update their existing playbooks by re-inserting | modifying
    | deleting the corresponding action blocks or by providing appropriate values to these action
    parameters to ensure the correct functioning of the playbooks created on the earlier versions of
    the app.

      

    -   Run Query - 3 new action parameters 'wait_for_results_processing',
        'return_when_n\_results_available', 'wait_for_n\_results_available' are added which helps to
        limit the data fetched from the Tanium server.

-   New action 'Get Question Results' has been added. Hence, it is requested to the end-user to
    please update their existing playbooks by inserting the corresponding action blocks for this
    action on the earlier versions of the app.

## Port Information

The app uses HTTP/ HTTPS protocol for communicating with the Tanium server. Below are the default
ports used by Splunk SOAR.

|         Service Name | Transport Protocol | Port |
|----------------------|--------------------|------|
|         http         | tcp                | 80   |
|         https        | tcp                | 443  |

## Asset Configuration

-   **Consider question results complete at (% out of 100)**

      

    -   Consider Tanium question results complete at this value, a percentage out of 100. This
        parameter impacts the **run query** and **list processes** actions only. Note that a similar
        value can be defined in Tanium user preferences – you might want to reflect the same value
        in your app asset configuration as you use in your Tanium user configuration. The time spent
        returning your results is dependent on how much data you have on your Tanium instance and
        you may want your action to end with a certain percentage threshold instead of waiting for
        Tanium to return 100% of the results.

-   **API Token**

      

    -   An API token can be used for authentication in place of the basic auth method of username
        and password. If the asset is configured with **both** API token and username/password
        credentials, the token will be used as the preferred method. However for security purposes,
        once the token has expired or if it is invalid, the app will **NOT** revert to basic auth
        credentials - the token must either be removed from or replaced in the asset config.

## API Token Generation

-   There are different methods of creating an API token depending on which version of Tanium is
    being used. Later versions allow token generation through the UI, while earlier versions require
    the use of curl commands.

-   **IMPORTANT: The default expiration of a generated token is 7 days. To reduce maintenance, we
    recommend setting the default expiration to 365 days. Note that you will have to repeat this
    process to generate a new token before the current token expires. Failure to do so will cause
    integration to break as your token will no longer be valid after such date.**

-   **The end user will need to add the SOAR source IP address as a "Trusted IP Address" when
    creating a Tanium API Token. They will also need to note the expiration time and create a new
    token accordingly.**

-   **The following information regarding API calls using curl commands and additional notes have
    been taken from the "Tanium Server REST API Reference" documentation. More information can be
    gathered by contacting Tanium Support.**

      

    ### UI

-   To generate an API token in the UI and to configure the system to use it, please follow the
    steps mentioned in this
    [documentation](https://docs.tanium.com/platform_user/platform_user/console_api_tokens.html) .
    On Tanium 7.5.2.3503, new API tokens can be generated by selecting Administration \> Permissions
    \> API Tokens \> New API Token. Depending on the version of Tanium, the UI may not contain the
    token creation button on the page and will only display a list of the existing API tokens. If
    this is the case, you will need to use the curl command method.

      

    ### Curl

-   To generate an API token using this method, a session string or token string will need to be
    acquired first through the Login API endpoint. Then, the session or token string will be passed
    in the header to get the API token. In the examples below, fields need to be passed in the API
    token request. **You MUST include the SOAR IP address as a trusted IP address.** It is also
    useful to include the **notes** field, as this can be useful in identifying the token after it
    is created since the token string is not visible in the UI using this method.

-   #### Login API Endpoint

      
    `       /api/v2/session/login      `

    #### Example Request

    `       $ curl -s -X POST --data-binary @sample_login.json https://localhost/api/v2/session/login      `

              # where sample_login.json contains:
              # {
              #   "username": "jane.doe",
              #   "domain": "dev",
              #   "password": "TESTPASS" 
              # }
              

    #### Example Response

              {
                "data": {
                    "session": "1-224-3cb8fe975e0b505045d55584014d99f6510c110d19d0708524c1219dbf717535"
                    }
              }
                

-   #### Token API Endpoint

      
    `       /api/v2/api_tokens      `

    #### Example Request (session string):

    `       $ curl -s -X POST -H "session:{string}" --data "{json object}" https://localhost/api/v2/api_tokens      `

    #### Header Parameters

    | Field   | Type   | Description                                                                                                      |
    |---------|--------|------------------------------------------------------------------------------------------------------------------|
    | session | string | (Required) The Tanium session or token string. The session string is returned by the Log In and Validate routes. |

    #### Body Parameters

    | Field  | Type             | Description                                                                                                                                                                         |
    |--------|------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
    | object | application/json | (Required) A json object containing fields "expire_in_days", "notes", and "trusted_ip_addresses". Be sure that the SOAR IP address is included in the "trusted_ip_addresses" field. |

    #### Example Request (with fields):

    `       $ curl -s -X POST -H "session:{string}" --data-binary @new_token.json https://localhost/api/v2/api_tokens      `

              # where new_token.json contains:
              # {
              #   "expire_in_days": 365,
              #   "notes": "My module token.",
              #   "trusted_ip_addresses": "10.10.10.15,192.168.3.0/24"
              # }
                

## Permissions for Interacting with Tanium REST API

-   **Actions may fail if the account you are using to connect to Tanium does not have sufficient
    permissions.**

      
      

<!-- -->

-   Computer Groups

      

    -   A component of Tanium permissions is the “Computer Groups” which an account can operate on.
        Please ensure the account you used to configure the Tanium REST API app has access to any
        machines you run queries or actions on.

      

-   Suggested Roles for SOAR Account in Tanium

      

    -   The following Tanium Roles shown below can be configured within Tanium and applied to the
        account used to connect to SOAR. Note that these roles represent guidance by the Splunk SOAR
        team based on testing against Tanium 7.3.314. **The permissions required in your environment
        may vary.**

    -   On Tanium 7.3.314, roles can be configured by selecting Permissions \> Roles in the Tanium
        UI. Roles can be applied to a user account by selecting Administration \> Users \> (View
        User) \> Edit Roles in the Tanium UI.

    -   Alternatively, you can **Import from XML** directly under Permissions \> Roles in the Tanium
        UI. The XML files containing the roles described below are attached to this app's folder.

          
          
        `                     Role #1 Name:                    SOAR All Questions         `

        -   `                         Permissions:                        Can Ask Question and Saved Question. Needed for run query and list processes actions.           `
        -   `                         Ask Dynamic Question:                        Yes           `
        -   `                         Show Interact:                        Yes           `
        -   `                         Advanced Permissions:                        Read Sensor, Read Saved Question           `

        `                               Role #2 Name:                    SOAR Actions         `

        -   `                         Permissions:                        Can execute actions only. Needed for execute action and terminate process.           `
        -   `                         Show Interact:                        Yes           `
        -   `                         Advanced Permissions:                        Read Action, Write Action, Read Package           `

## Pagination

-   Pagination is not implemented in this release. So, the results for the actions mentioned below
    will be the results that are fetched in a single API call.

      

    -   List processes
    -   List questions
    -   Run query

## How to use Run Query Action

-   The **Run Query** action uses **Tanium's Interact Question Bar** to ask questions to retrieve
    information from endpoints. For example, you can ask a question that determines whether any
    endpoints are missing critical security patches.

-   Parameter Information:  
    These parameters modify questions asked using one of the two modes of operation specified below.
    -   **wait_for_results_processing:** Some long-running sensors return intermediate results with
        the contents "results currently unavailable", and then [later the sensor fills in the
        results](https://docs.tanium.com/interact/interact/results.html#:~:text=Results%20Currently%20Unavailable)
        . This option instructs the App to wait until the results are returned to Tanium and only
        after that return the final results. The waiting is still time bounded by the
        **timeout_seconds** setting.
    -   **return_when_n\_results_available:** When set, the Tanium REST App will return results to
        the playbook as soon as \`N\` results are returned, even if the **Consider question results
        complete at (% out of 100)** percentage has not been met. This is useful in scenarios where
        the playbook expects to get at most \`N\` results, and wants to return as soon as this
        occurs.
    -   **wait_for_n\_results_available:** When set, the Tanium REST App will wait (up to the
        **timeout_seconds** timeout) until at least \`N\` results are returned. This is helpful in
        situations where the Tanium server is under high utilization. Sometimes the App will
        estimate that 100% of hosts have reported results, even when there are a few stragglers
        left. If the playbook author knows that it should be getting \`N\` results, this will wait
        past the **Consider question results complete at (% out of 100)** percentage.

-   Two modes of operation are supported for the run query action:

      
      

    -   Manual Questions
        -   Using Tanium question syntax, users can directly provide the question to be asked to the
            Tanium server in the **query_text** parameter. For more information on Tanium's question
            syntax, [click here.](https://docs.tanium.com/interact/interact/questions.html)

        -   Make sure the **is_saved_question** box is unchecked since you are providing a question
            from scratch.

        -   Use the **group name** parameter to run your query on a particular computer group in
            your Tanium instance. Users can create a computer group with specific IP
            addresses/hostnames on the Tanium UI under Administration>Computer Groups. For a guide
            on how to create/manage computer groups in Tanium, [click
            here.](https://docs.tanium.com/platform_user/platform_user/console_computer_groups.html)

              

            -   NOTE: If the **group_name** parameter is not provided, the query will be executed on
                all registered IP addresses/hostnames in your Tanium instance.

              

        -   Parameterized Query

              

            -   Users can provide the parameter(s) of a Parameterized query in square
                brackets(\[parameter-1, parameter-2, ..., parameter-n\]).

                  

                -   Example: Get Process Details\["parameter-1","parameter-2"\] from all machines
                    with Computer Name contains localhost

            -   Users can ignore the parameter part in the query if they want the default value to
                be considered. Below are the 2 ways a user can achieve this:

                  

                -   Query: Get Process Details from all machines with Computer Name contains
                    localhost
                -   Query: Get Process Details\["",""\] from all machines with Computer Name
                    contains localhost

            -   If a user wants to add only one parameter out of two parameters, users can keep the
                parameter empty. Below are the examples:

                  

                -   Example: Get Process Details\["parameter-1",""\] from all machines with Computer
                    Name contains localhost
                -   Example: Get Process Details\["","parameter-2"\] from all machines with Computer
                    Name contains localhost

            -   For two or more sensors in a query, users can select one of the below:

                  

                -   Provide value for all the parameters of all the sensors in the query

                      

                    -   Example: Get Child Processes\["parameter-1"\] and Process
                        Details\["parameter-2","parameter-3"\] from all machines

                -   Do not provide value for any of the parameters of any of the sensors in the
                    query

                      

                    -   Example: Get Child Processes and Process Details from all machines

                -   Provide value for the parameters you want to provide. The parameters for which
                    you don't want to add value, please use double quotes("")

                      

                    -   Example: Get Child Processes\[""\] and Process Details\["SHA1", ""\] from
                        all machines
                    -   Example: Get Child Processes\["csrss.exe"\] and Process Details\["", ""\]
                        from all machines

                  

            -   Scenarios:

                  

                1.  If the Child Processes sensor expects 1 parameter and Process Details expects 2
                    parameters. But the user provides only 2 parameters instead of 3, then action
                    will fail with a proper error message.
                    -   Example: Get Child Processes\["parameter-1"\] and Process
                        Details\["parameter-2"\] from all machines
                2.  If the Child Processes sensor expects 1 parameter and Process Details expects 2
                    parameters. But the user provides more than 3 parameters, then action will fail
                    with a proper error message.
                    -   Example: Get Child Processes\["parameter-1", "parameter-2"\] and Process
                        Details\["parameter-3", "parameter-4"\] from all machines
                3.  If the Child Processes sensor expects 1 parameter and Process Details expects 2
                    parameters. But if the user does not provide any parameter in the Child
                    Processes sensor and 3 parameters in Process Details sensor, then the first
                    parameter from Process Details will be considered as the only parameter of the
                    Child Processes sensor and the action will fetch the results accordingly.
                    -   Query provided: Get Child Processes and Process Details\["parameter-1",
                        "parameter-2", "parameter-3"\] from all machines
                    -   Query that will be executed because of API limitations: Get Child
                        Processes\["parameter-1"\] and Process Details\["parameter-2",
                        "parameter-3"\] from all machines
                4.  If the Child Processes sensor expects 1 parameter and Process Details expects 2
                    parameters. But if the user provides 2 parameters in Child Processes sensor and
                    1 parameter in Process Details sensor, then the second parameter from Child
                    Processes sensor will be considered as the first parameter of the Process
                    Details sensor and the only parameter of the Process Details sensor will be
                    considered as the second parameter of the same. The action will fetch the
                    results accordingly.
                    -   Query provided: Get Child Processes\["parameter-1", "parameter-2"\] and
                        Process Details\["parameter-3"\] from all machines
                    -   Query that will be executed because of API limitations: Get Child
                        Processes\["parameter-1"\] and Process Details\["parameter-2",
                        "parameter-3"\] from all machines

        -   Example Run 1 - Get Computer Name:

              

            -   `                             query text                            : Get Computer Name from all machines             `

            -   `                             is saved question                            : False             `

            -   `                             group name                            :             `

            -   `                             timeout seconds                            : 600             `

                  
                `                             `

        -   Example Run 2 - Get Computer Name for Specified Computer Group:

              

            -   `                             query text                            : Get Computer Name from all machines             `

            -   `                             is saved question                            : False             `

            -   `                             group name                            : centos-computers             `

            -   `                             timeout seconds                            : 600             `

                  
                `                             `

        -   Example Run 3 - A Complex Query:

              

            -   `                             query text                            : Get Trace Executed Processes[1 month,1522723342293|1522726941293,0,0,10,0,rar.exe,"",-hp,"","",""] from all machines             `

            -   `                             is saved question                            : False             `

            -   `                             group name                            :             `

            -   `                             timeout seconds                            : 600             `

                  
                `                             `

        -   Example Run 4 - List Process Details for a Specified Device:

              

            -   `                             query text                            : Get Process Details["",""] from all machines with Computer Name contains localhost             `

            -   `                             is saved question                            : False             `

            -   `                             group name                            : centos-computers             `

            -   `                             timeout seconds                            : 600             `

                  
                `                             `

          

    -   Saved Questions

          

        -   Users can create 'Saved Questions' on the Tanium UI under Content>Saved Questions and
            provide the name of that saved question in the **query_text** parameter to fetch
            appropriate results. For a guide on how to create/manage the Saved Questions on your
            Tanium instance, [click
            here.](https://docs.tanium.com/interact/interact/saving_questions.html)

        -   The **is_saved_question** box must be checked for this to work correctly.

              
              

        -   Example Run:

              

            -   `                               query text                              : My Computers              `

            -   `                               is saved question                              : True              `

            -   `                               timeout seconds                              : 600              `

                  
                `                               `

  

## How to use Terminate Process Action

-   Please follow the steps below to execute this action successfully:

      

    -   Create and save a package on the Tanium server with a meaningful package name and add a
        command to terminate the required process in the package's command section.
    -   To terminate the process of particular computers, users can create a computer group with the
        IP address/hostname of the target computers and can specify that group name in the
        **group_name** parameter.
    -   If the **group_name** parameter is not provided, then the terminate process action will be
        executed on all the registered IP addresses/hostnames.

  

## How to use Execute Action

-   The 'Execute Action' action will cause a specified Tanium Package to be executed on the
    specified group.

      

    -   Create and save a package on the Tanium server with a meaningful package name and add a
        command in the package's command section, or just use an existing package.

    -   Any parameters required by the specified package must be supplied with a valid JSON via the
        **package_parameters** parameter. For example,
        `         {"$1":"Standard_Collection", "$2":"SCP"}        `

    -   To execute this action on particular computers, users can create a computer group with the
        IP address/hostname of the target computers and can specify that group name in the
        **group_name** parameter.

    -   If the **group_name** parameter is not provided, then the action will be executed on all the
        registered IP addresses/hostnames.

    -   Example Run:

          

        -   `                         action name                        : Splunk Live Response Test           `

        -   `                         action group                        : Default           `

        -   `                         package name                        : Live Response - Linux           `

        -   `                         package parameters                        : {"$1":"Standard_Collection", "$2":"SCP"}           `

        -   `                         group name                        : centos-computers           `

              
            `                         `

  


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Tanium REST asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**base_url** |  required  | string | Base URL (e.g. https://taniumserver)
**api_token** |  optional  | password | API Token
**username** |  optional  | string | Username
**password** |  optional  | password | Password
**verify_server_cert** |  optional  | boolean | Verify Server Certificate
**results_percentage** |  optional  | numeric | Consider question results complete at (% out of 100)

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration  
[list processes](#action-list-processes) - List the running processes of the devices registered on the Tanium server  
[parse question](#action-parse-question) - Parses the supplied text into a valid Tanium query string  
[list questions](#action-list-questions) - Retrieves either a history of the most recent questions or a list of saved questions  
[terminate process](#action-terminate-process) - Kill a running process of the devices registered on the Tanium server  
[execute action](#action-execute-action) - Execute an action on the Tanium server  
[run query](#action-run-query) - Run a search query on the devices registered on the Tanium server  
[get question results](#action-get-question-results) - Return the results for an already asked question  

## action: 'test connectivity'
Validate the asset configuration for connectivity using supplied configuration

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'list processes'
List the running processes of the devices registered on the Tanium server

Type: **investigate**  
Read only: **True**

This action requires specifying a sensor to be used to list processes. A standard Tanium sensor, 'Process Details' is used by default but a different sensor can be specified instead. Note that the 'Process Details' sensor may not be available on all Tanium deployments. Note that at this time this action only supports limiting the query to specified computer groups, but a generic Run Query action can be constructed to query an in individual computer's processes. As pagination is not implemented, the result(s) of the action will be the result(s) that are fetched in a single API call.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**sensor** |  required  | Sensor which will list all the processes | string | 
**group_name** |  optional  | Computer group name of which the processes will be listed | string | 
**timeout_seconds** |  required  | The number of seconds before the question expires | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.group_name | string |  |   tanium-01 
action_result.parameter.sensor | string |  |   Running Processes With User 
action_result.parameter.timeout_seconds | numeric |  |   60 
action_result.data.\*.data.max_available_age | string |  |  
action_result.data.\*.data.now | string |  |   2019/07/24 11:43:42 GMT-0000 
action_result.data.\*.data.result_sets.\*.age | numeric |  |   0 
action_result.data.\*.data.result_sets.\*.archived_question_id | numeric |  `taniumrest question id`  |   0 
action_result.data.\*.data.result_sets.\*.cache_id | string |  |   12418149 
action_result.data.\*.data.result_sets.\*.columns.\*.hash | numeric |  |   3744593586 
action_result.data.\*.data.result_sets.\*.columns.\*.name | string |  |   Process 
action_result.data.\*.data.result_sets.\*.columns.\*.type | numeric |  |   1 
action_result.data.\*.data.result_sets.\*.error_count | numeric |  |   0 
action_result.data.\*.data.result_sets.\*.estimated_total | numeric |  |   2 
action_result.data.\*.data.result_sets.\*.expiration | numeric |  |   0 
action_result.data.\*.data.result_sets.\*.expire_seconds | numeric |  |   0 
action_result.data.\*.data.result_sets.\*.filtered_row_count | numeric |  |   35 
action_result.data.\*.data.result_sets.\*.filtered_row_count_machines | numeric |  |   53 
action_result.data.\*.data.result_sets.\*.id | numeric |  `taniumrest question id`  |   58456 
action_result.data.\*.data.result_sets.\*.issue_seconds | numeric |  |   0 
action_result.data.\*.data.result_sets.\*.item_count | numeric |  |   35 
action_result.data.\*.data.result_sets.\*.mr_passed | numeric |  |   2 
action_result.data.\*.data.result_sets.\*.mr_tested | numeric |  |   2 
action_result.data.\*.data.result_sets.\*.no_results_count | numeric |  |   0 
action_result.data.\*.data.result_sets.\*.passed | numeric |  |   2 
action_result.data.\*.data.result_sets.\*.question_id | numeric |  `taniumrest question id`  |   58456 
action_result.data.\*.data.result_sets.\*.report_count | numeric |  |   2 
action_result.data.\*.data.result_sets.\*.row_count | numeric |  |   35 
action_result.data.\*.data.result_sets.\*.row_count_machines | numeric |  |   53 
action_result.data.\*.data.result_sets.\*.rows.\*.cid | numeric |  |   0 
action_result.data.\*.data.result_sets.\*.rows.\*.data.\*.text | string |  |   TaniumModuleServer.exe 
action_result.data.\*.data.result_sets.\*.rows.\*.id | numeric |  |   58783672 
action_result.data.\*.data.result_sets.\*.saved_question_id | numeric |  |   0 
action_result.data.\*.data.result_sets.\*.seconds_since_issued | numeric |  |   0 
action_result.data.\*.data.result_sets.\*.select_count | numeric |  |   1 
action_result.data.\*.data.result_sets.\*.tested | numeric |  |   2 
action_result.summary.num_results | numeric |  |   864 
action_result.summary.timeout_seconds | numeric |  |   10 
action_result.message | string |  |   Num results: 864 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'parse question'
Parses the supplied text into a valid Tanium query string

Type: **investigate**  
Read only: **True**

<p>When asked a non-saved question in the <b>query_text</b> parameter, it will parse the given query and give a list of suggestions that are related to it.</p><p>For example, on the Tanium platform, if one were to just ask the question, 'all IP addresses,' Tanium will give the suggestions:<br><ul><li>Get Static IP Addresses from all machines</li><li>Get IP Routes from all machines</li><li>Get IP Address from all machines</li><li>Get IP Connections from all machines</li><li>Get IP Route Details from all machines</li><li>Get Network IP Gateway from all machines</li></ul><br>Tanium sorts this list, from most-related to least-related.</p>

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**query_text** |  required  | Query text to parse | string |  `taniumrest question text` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.query_text | string |  `taniumrest question text`  |   processes 
action_result.data.\*.expire_seconds | numeric |  |   600 
action_result.data.\*.force_computer_id_flag | numeric |  |  
action_result.data.\*.from_canonical_text | numeric |  |   0 
action_result.data.\*.group | string |  `taniumrest group definition`  |   { group id object } 
action_result.data.\*.question_text | string |  `taniumrest question text`  |   Get Child Processes from all machines 
action_result.data.\*.score | numeric |  |   7082 
action_result.data.\*.selects.\*.filter.all_values_flag | boolean |  |   True  False 
action_result.data.\*.selects.\*.filter.delimiter | string |  |  
action_result.data.\*.selects.\*.filter.delimiter_index | numeric |  |  
action_result.data.\*.selects.\*.filter.ignore_case_flag | boolean |  |   True  False 
action_result.data.\*.selects.\*.filter.max_age_seconds | numeric |  |  
action_result.data.\*.selects.\*.filter.not_flag | boolean |  |   True  False 
action_result.data.\*.selects.\*.filter.operator | string |  |   RegexMatch 
action_result.data.\*.selects.\*.filter.substring_flag | boolean |  |   True  False 
action_result.data.\*.selects.\*.filter.substring_length | numeric |  |  
action_result.data.\*.selects.\*.filter.substring_start | numeric |  |  
action_result.data.\*.selects.\*.filter.value | string |  |  
action_result.data.\*.selects.\*.filter.value_type | string |  |   String 
action_result.data.\*.selects.\*.sensor.delimiter | string |  |   , 
action_result.data.\*.selects.\*.sensor.hash | numeric |  |   3867657808 
action_result.data.\*.selects.\*.sensor.id | numeric |  |   350 
action_result.data.\*.selects.\*.sensor.max_age_seconds | numeric |  |   86400 
action_result.data.\*.selects.\*.sensor.name | string |  |   Child Processes 
action_result.data.\*.selects.\*.sensor.parameter_definition | string |  |  
action_result.data.\*.selects.\*.sensor.value_type | string |  |   String 
action_result.data.\*.sensor_references.\*.name | string |  |   Child Processes 
action_result.data.\*.sensor_references.\*.real_ms_avg | numeric |  |   0 
action_result.data.\*.sensor_references.\*.start_char | string |  |   4 
action_result.data.\*.skip_lock_flag | numeric |  |  
action_result.summary.number_of_parsed_questions | numeric |  |   7 
action_result.message | string |  |   Num parsed questions: 7 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'list questions'
Retrieves either a history of the most recent questions or a list of saved questions

Type: **investigate**  
Read only: **True**

If the <b>list_saved_questions</b> parameter is true, this action will return a list of saved questions. If the flag is not set, this action will return the history of recently asked questions. As pagination is not implemented, the result(s) of the action will be the result(s) that are fetched in a single API call.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**list_saved_questions** |  optional  | Retrieve Saved Questions | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.list_saved_questions | boolean |  |   True  False 
action_result.data.\*.action_tracking_flag | boolean |  |   True  False 
action_result.data.\*.archive_enabled_flag | boolean |  |   True  False 
action_result.data.\*.archive_owner | string |  |  
action_result.data.\*.archive_owner.id | numeric |  |   1 
action_result.data.\*.archive_owner.name | string |  |   administrator 
action_result.data.\*.content_set.id | numeric |  |   7 
action_result.data.\*.content_set.name | string |  |   Detect Service 
action_result.data.\*.context_group.id | numeric |  |  
action_result.data.\*.expiration | string |  |   2001-01-01T00:00:00Z 
action_result.data.\*.expire_seconds | numeric |  |   600 
action_result.data.\*.hidden_flag | boolean |  |   True  False 
action_result.data.\*.id | numeric |  `taniumrest question id`  |   26 
action_result.data.\*.is_expired | boolean |  |   True  False 
action_result.data.\*.issue_seconds | numeric |  |   300 
action_result.data.\*.issue_seconds_never_flag | boolean |  |   True  False 
action_result.data.\*.keep_seconds | numeric |  |   0 
action_result.data.\*.management_rights_group.id | numeric |  |  
action_result.data.\*.metadata.\*.admin_flag | boolean |  |   True  False 
action_result.data.\*.metadata.\*.name | string |  |   SQPreference_Default 
action_result.data.\*.metadata.\*.value | string |  |   {"default_grid_zoom_level":0,"default_line_zoom_level":12,"default_tab":1,"merge_flag":0,"drilldown_flag":0} 
action_result.data.\*.mod_time | string |  |   2019-02-11T21:22:25Z 
action_result.data.\*.mod_user.display_name | string |  |  
action_result.data.\*.mod_user.domain | string |  `domain`  |  
action_result.data.\*.mod_user.id | numeric |  |   1 
action_result.data.\*.mod_user.name | string |  |   administrator 
action_result.data.\*.most_recent_question_id | numeric |  `taniumrest question id`  |   56071 
action_result.data.\*.name | string |  |   Detect Managed Unix Endpoints 
action_result.data.\*.packages.\*.id | numeric |  |   1 
action_result.data.\*.packages.\*.name | string |  |   Distribute Tanium Standard Utilities 
action_result.data.\*.public_flag | boolean |  |   True  False 
action_result.data.\*.query_text | string |  `taniumrest question text`  |   Get Detect Tools Status from all machines with ( Detect Tools Status contains engine version and Detect Tools Status contains Unix ) 
action_result.data.\*.question.id | numeric |  `taniumrest question id`  |   56071 
action_result.data.\*.row_count_flag | boolean |  |   True  False 
action_result.data.\*.saved_question.id | numeric |  |   15 
action_result.data.\*.skip_lock_flag | boolean |  |   True  False 
action_result.data.\*.sort_column | numeric |  |   0 
action_result.data.\*.user.deleted_flag | boolean |  |   True  False 
action_result.data.\*.user.id | numeric |  |   1 
action_result.data.\*.user.name | string |  |   administrator 
action_result.summary.num_questions | numeric |  |   818 
action_result.summary.num_saved_questions | numeric |  |   32 
action_result.message | string |  |   Num saved questions: 32 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'terminate process'
Kill a running process of the devices registered on the Tanium server

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**action_name** |  required  | Name of the action | string | 
**action_group** |  required  | Group of the action | string | 
**package_name** |  required  | Package name that will be executed | string | 
**package_parameters** |  optional  | Package parameters of the corresponding package | string | 
**group_name** |  optional  | Computer group name of which the process will be terminated | string | 
**distribute_seconds** |  optional  | The number of seconds over which to deploy the action | numeric | 
**issue_seconds** |  optional  | The number of seconds to reissue an action from the saved action | numeric | 
**expire_seconds** |  required  | The duration from the start time before the action expires | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.action_group | string |  |   Default 
action_result.parameter.action_name | string |  |   test terminate process 
action_result.parameter.distribute_seconds | numeric |  |   60 
action_result.parameter.expire_seconds | numeric |  |   600 
action_result.parameter.group_name | string |  |   tanium-01 
action_result.parameter.issue_seconds | numeric |  |   30 
action_result.parameter.package_name | string |  |   terminate process 
action_result.parameter.package_parameters | string |  |  
action_result.data.\*.action_group_id | numeric |  |   151 
action_result.data.\*.approved_flag | boolean |  |   True  False 
action_result.data.\*.approver.id | numeric |  |   1 
action_result.data.\*.approver.name | string |  |   administrator 
action_result.data.\*.comment | string |  |  
action_result.data.\*.creation_time | string |  |   2019-09-18T04:53:58Z 
action_result.data.\*.distribute_seconds | numeric |  |   0 
action_result.data.\*.end_time | string |  |   Never 
action_result.data.\*.expire_seconds | numeric |  |   600 
action_result.data.\*.id | numeric |  |   523 
action_result.data.\*.issue_count | numeric |  |   0 
action_result.data.\*.issue_seconds | numeric |  |   0 
action_result.data.\*.last_action.id | numeric |  |   272936 
action_result.data.\*.last_action.start_time | string |  |   Never 
action_result.data.\*.last_action.target_group.id | numeric |  |   3646 
action_result.data.\*.last_start_time | string |  |   Never 
action_result.data.\*.name | string |  |   test terminate process 
action_result.data.\*.next_start_time | string |  |   Never 
action_result.data.\*.package_spec.available_time | string |  |   2001-01-01T00:00:00Z 
action_result.data.\*.package_spec.command | string |  |   cmd /c mkdir C:\\Users\\Administrator\\some_dir\\ 
action_result.data.\*.package_spec.command_timeout | numeric |  |   600 
action_result.data.\*.package_spec.content_set.id | numeric |  |   9 
action_result.data.\*.package_spec.content_set.name | string |  |  
action_result.data.\*.package_spec.creation_time | string |  |   2001-01-01T00:00:00Z 
action_result.data.\*.package_spec.deleted_flag | boolean |  |   True  False 
action_result.data.\*.package_spec.display_name | string |  |  
action_result.data.\*.package_spec.expire_seconds | numeric |  |   3600 
action_result.data.\*.package_spec.files.\*.bytes_downloaded | numeric |  |  
action_result.data.\*.package_spec.files.\*.bytes_total | numeric |  |   39221 
action_result.data.\*.package_spec.files.\*.cache_status | string |  |   Cached 
action_result.data.\*.package_spec.files.\*.download_seconds | numeric |  |  
action_result.data.\*.package_spec.files.\*.download_start_time | string |  |   2021-11-16T18:53:31Z 
action_result.data.\*.package_spec.files.\*.hash | string |  |   b6c7534b828ff6e28f1467041a6f6f9a5ad7a7f4ac367c5425f16e249c77ec30 
action_result.data.\*.package_spec.files.\*.id | numeric |  |   73 
action_result.data.\*.package_spec.files.\*.last_download_progress_time | string |  |   2021-11-16T18:53:31Z 
action_result.data.\*.package_spec.files.\*.name | string |  |   clean-stale-tanium-client-data.vbs 
action_result.data.\*.package_spec.files.\*.size | numeric |  |   39221 
action_result.data.\*.package_spec.files.\*.source | string |  |  
action_result.data.\*.package_spec.files.\*.status | numeric |  |   200 
action_result.data.\*.package_spec.hidden_flag | boolean |  |   True  False 
action_result.data.\*.package_spec.id | numeric |  |   600 
action_result.data.\*.package_spec.last_modified_by | string |  |  
action_result.data.\*.package_spec.last_update | string |  |   2019-09-18T04:53:58Z 
action_result.data.\*.package_spec.mod_user.display_name | string |  |  
action_result.data.\*.package_spec.mod_user.domain | string |  `domain`  |  
action_result.data.\*.package_spec.mod_user.id | numeric |  |   0 
action_result.data.\*.package_spec.mod_user.name | string |  |  
action_result.data.\*.package_spec.modification_time | string |  |   2001-01-01T00:00:00Z 
action_result.data.\*.package_spec.name | string |  |   terminate process 
action_result.data.\*.package_spec.process_group_flag | boolean |  |   True  False 
action_result.data.\*.package_spec.skip_lock_flag | boolean |  |   True  False 
action_result.data.\*.package_spec.source_hash | string |  `sha256`  |   b75af868db6d80c0e603ce8827146e2e44f2728c6ae98fd6082003412cf3a207 
action_result.data.\*.package_spec.source_hash_changed_flag | boolean |  |   True  False 
action_result.data.\*.package_spec.source_id | numeric |  |   221 
action_result.data.\*.package_spec.verify_expire_seconds | numeric |  |   3600 
action_result.data.\*.package_spec.verify_group.id | numeric |  |   0 
action_result.data.\*.package_spec.verify_group_id | numeric |  |   0 
action_result.data.\*.policy_flag | boolean |  |   True  False 
action_result.data.\*.public_flag | boolean |  |   True  False 
action_result.data.\*.start_now_flag | boolean |  |   True  False 
action_result.data.\*.start_time | string |  |   2019-09-18T04:53:58Z 
action_result.data.\*.status | numeric |  |   0 
action_result.data.\*.target_group.id | numeric |  |   3646 
action_result.data.\*.user.id | numeric |  |   1 
action_result.data.\*.user.name | string |  |   administrator 
action_result.data.\*.user_start_time | string |  |   2001-01-01T00:00:00Z 
action_result.summary | string |  |  
action_result.message | string |  |   Successfully executed the action 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'execute action'
Execute an action on the Tanium server

Type: **generic**  
Read only: **False**

<li>See top-level app documentation for example parameters.</li><li>If a parameterized package is used for executing an action all the parameters must be provided with correct and unique keys. If any key is repeated then the value of that key will be overwritten.</li><li>If the <b>issue_seconds</b> parameter is provided, then the action will respawn after a time interval provided in the <b>issue_seconds</b> parameter.</li>

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**action_name** |  required  | Creates a name for the action executed | string | 
**action_group** |  required  | Group of the action | string | 
**package_name** |  required  | Name of the Tanium package to be executed | string | 
**package_parameters** |  optional  | Parameter inputs of the corresponding package. Provide JSON format (i.e. {"$1": "Standard_Collection", "$2": "SCP"}) | string | 
**group_name** |  optional  | The Tanium Computer Group name on which the action will be executed. If left blank, will execute on all registered IP addresses/hostnames in your Tanium instance | string |  `taniumrest group definition` 
**distribute_seconds** |  optional  | The number of seconds over which to deploy the action | numeric | 
**issue_seconds** |  optional  | The number of seconds to reissue an action from the saved action | numeric | 
**expire_seconds** |  required  | The duration from the start time before the action expires | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.action_group | string |  |   Default 
action_result.parameter.action_name | string |  |   test action start 7 
action_result.parameter.distribute_seconds | numeric |  |   60 
action_result.parameter.expire_seconds | numeric |  |   600 
action_result.parameter.group_name | string |  `taniumrest group definition`  |   tanium-01 
action_result.parameter.issue_seconds | numeric |  |   30 
action_result.parameter.package_name | string |  |   make directory 
action_result.parameter.package_parameters | string |  |   {"$1": "TestDirectory"} 
action_result.data.\*.action_group_id | numeric |  |   151 
action_result.data.\*.approved_flag | boolean |  |   True  False 
action_result.data.\*.approver.id | numeric |  |   1 
action_result.data.\*.approver.name | string |  |   administrator 
action_result.data.\*.comment | string |  |  
action_result.data.\*.creation_time | string |  |   2019-09-16T07:43:57Z 
action_result.data.\*.distribute_seconds | numeric |  |   0 
action_result.data.\*.end_time | string |  |   Never 
action_result.data.\*.expire_seconds | numeric |  |   600 
action_result.data.\*.id | numeric |  `taniumrest question id`  |   482 
action_result.data.\*.issue_count | numeric |  |   0 
action_result.data.\*.issue_seconds | numeric |  |   0 
action_result.data.\*.last_action.id | numeric |  |   272568 
action_result.data.\*.last_action.start_time | string |  |   Never 
action_result.data.\*.last_action.target_group.id | numeric |  |   3614 
action_result.data.\*.last_start_time | string |  |   Never 
action_result.data.\*.name | string |  |   test action start 7 
action_result.data.\*.next_start_time | string |  |   Never 
action_result.data.\*.package_spec.available_time | string |  |   2001-01-01T00:00:00Z 
action_result.data.\*.package_spec.command | string |  |   cmd /c mkdir C:\\Users\\Administrator\\test123\\"TestDirectory" 
action_result.data.\*.package_spec.command_timeout | numeric |  |   600 
action_result.data.\*.package_spec.content_set.id | numeric |  |   2 
action_result.data.\*.package_spec.content_set.name | string |  |  
action_result.data.\*.package_spec.creation_time | string |  |   2001-01-01T00:00:00Z 
action_result.data.\*.package_spec.deleted_flag | boolean |  |   True  False 
action_result.data.\*.package_spec.display_name | string |  |  
action_result.data.\*.package_spec.expire_seconds | numeric |  |   3600 
action_result.data.\*.package_spec.files.\*.bytes_downloaded | numeric |  |  
action_result.data.\*.package_spec.files.\*.bytes_total | numeric |  |   39221 
action_result.data.\*.package_spec.files.\*.cache_status | string |  |   Cached 
action_result.data.\*.package_spec.files.\*.download_seconds | numeric |  |  
action_result.data.\*.package_spec.files.\*.download_start_time | string |  |   2021-11-16T18:53:31Z 
action_result.data.\*.package_spec.files.\*.hash | string |  |   b6c7534b828ff6e28f1467041a6f6f9a5ad7a7f4ac367c5425f16e249c77ec30 
action_result.data.\*.package_spec.files.\*.id | numeric |  |   73 
action_result.data.\*.package_spec.files.\*.last_download_progress_time | string |  |   2021-11-16T18:53:31Z 
action_result.data.\*.package_spec.files.\*.name | string |  |   clean-stale-tanium-client-data.vbs 
action_result.data.\*.package_spec.files.\*.size | numeric |  |   39221 
action_result.data.\*.package_spec.files.\*.source | string |  |  
action_result.data.\*.package_spec.files.\*.status | numeric |  |   200 
action_result.data.\*.package_spec.hidden_flag | boolean |  |   True  False 
action_result.data.\*.package_spec.id | numeric |  |   559 
action_result.data.\*.package_spec.last_modified_by | string |  |  
action_result.data.\*.package_spec.last_update | string |  |   2019-09-16T07:43:57Z 
action_result.data.\*.package_spec.mod_user.display_name | string |  |  
action_result.data.\*.package_spec.mod_user.domain | string |  `domain`  |  
action_result.data.\*.package_spec.mod_user.id | numeric |  |   0 
action_result.data.\*.package_spec.mod_user.name | string |  |  
action_result.data.\*.package_spec.modification_time | string |  |   2001-01-01T00:00:00Z 
action_result.data.\*.package_spec.name | string |  |   make directory 
action_result.data.\*.package_spec.parameters.\*.key | string |  |   $1 
action_result.data.\*.package_spec.parameters.\*.type | numeric |  |   0 
action_result.data.\*.package_spec.parameters.\*.value | string |  |   TestDirectory 
action_result.data.\*.package_spec.process_group_flag | boolean |  |   True  False 
action_result.data.\*.package_spec.skip_lock_flag | boolean |  |   True  False 
action_result.data.\*.package_spec.source_hash | string |  `sha256`  |   d36e609e026380ce117388858503384ecd50f8fb9321ccaeab9647b4131cc7a7 
action_result.data.\*.package_spec.source_hash_changed_flag | boolean |  |   True  False 
action_result.data.\*.package_spec.source_id | numeric |  |   500 
action_result.data.\*.package_spec.verify_expire_seconds | numeric |  |   3600 
action_result.data.\*.package_spec.verify_group.id | numeric |  |   0 
action_result.data.\*.package_spec.verify_group_id | numeric |  |   0 
action_result.data.\*.policy_flag | boolean |  |   True  False 
action_result.data.\*.public_flag | boolean |  |   True  False 
action_result.data.\*.start_now_flag | boolean |  |   True  False 
action_result.data.\*.start_time | string |  |   2019-09-16T07:43:57Z 
action_result.data.\*.status | numeric |  |   0 
action_result.data.\*.target_group.id | numeric |  |   3614 
action_result.data.\*.user.id | numeric |  |   1 
action_result.data.\*.user.name | string |  |   administrator 
action_result.data.\*.user_start_time | string |  |   2001-01-01T00:00:00Z 
action_result.summary | string |  |  
action_result.message | string |  |   Successfully executed the action 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'run query'
Run a search query on the devices registered on the Tanium server

Type: **investigate**  
Read only: **True**

See top-level app documentation for example parameters. For manual questions only, the action waits for <b>timeout_seconds</b> provided by the user in intervals of 5 seconds to fetch the results. The action is a success as soon as the results are retrieved or else it will timeout and fail. As pagination is not implemented, the result(s) of the action will be the result(s) that are fetched in a single API call. If an endpoint takes longer than usual to evaluate a sensor, it might initially supply the answer[current results unavailable] to the answer message that it passes along the linear chain and ultimately to the Tanium Server. However, the sensor process continues on the endpoint after supplying that initial answer and, upon completing the process, the endpoint sends its updated answer. Reference Link: ~https://docs.tanium.com/interact/interact/results.html.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**query_text** |  required  | Query to run (in Tanium Question Syntax) | string |  `taniumrest question text` 
**group_name** |  optional  | The Tanium Computer Group name on which the query will be executed (manual query only) | string | 
**is_saved_question** |  optional  | Check this box if the query text parameter refers to a 'Saved Question' on your Tanium | boolean | 
**timeout_seconds** |  required  | The number of seconds before the question expires (manual query only) | numeric | 
**wait_for_results_processing** |  optional  | Flag to wait for endpoint to return full results | boolean | 
**return_when_n_results_available** |  optional  | Return results as soon as 'n' answers are available | numeric | 
**wait_for_n_results_available** |  optional  | Wait until 'n' results are present, even if hit the percent complete threshold | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.group_name | string |  |   tanium-01 
action_result.parameter.is_saved_question | boolean |  |   False  True 
action_result.parameter.query_text | string |  `taniumrest question text`  |   Computer name 
action_result.parameter.return_when_n_results_available | numeric |  |   10 
action_result.parameter.timeout_seconds | numeric |  |   600 
action_result.parameter.wait_for_n_results_available | numeric |  |   10 
action_result.parameter.wait_for_results_processing | boolean |  |   False  True 
action_result.data.\*.data.max_available_age | string |  |  
action_result.data.\*.data.now | string |  |   2019/07/24 07:53:06 GMT-0000 
action_result.data.\*.data.result_sets.\*.age | numeric |  |   0 
action_result.data.\*.data.result_sets.\*.archived_question_id | numeric |  |   0 
action_result.data.\*.data.result_sets.\*.cache_id | string |  |   2668614289 
action_result.data.\*.data.result_sets.\*.columns.\*.hash | numeric |  |   3112892791 
action_result.data.\*.data.result_sets.\*.columns.\*.name | string |  |   DNS Server 
action_result.data.\*.data.result_sets.\*.columns.\*.type | numeric |  |   5 
action_result.data.\*.data.result_sets.\*.error_count | numeric |  |   0 
action_result.data.\*.data.result_sets.\*.estimated_total | numeric |  |   2 
action_result.data.\*.data.result_sets.\*.expiration | numeric |  |   0 
action_result.data.\*.data.result_sets.\*.expire_seconds | numeric |  |   0 
action_result.data.\*.data.result_sets.\*.filtered_row_count | numeric |  |   1 
action_result.data.\*.data.result_sets.\*.filtered_row_count_machines | numeric |  |   1 
action_result.data.\*.data.result_sets.\*.id | numeric |  `taniumrest question id`  |   58377 
action_result.data.\*.data.result_sets.\*.issue_seconds | numeric |  |   0 
action_result.data.\*.data.result_sets.\*.item_count | numeric |  |   1 
action_result.data.\*.data.result_sets.\*.mr_passed | numeric |  |   1 
action_result.data.\*.data.result_sets.\*.mr_tested | numeric |  |   2 
action_result.data.\*.data.result_sets.\*.no_results_count | numeric |  |   0 
action_result.data.\*.data.result_sets.\*.passed | numeric |  |   1 
action_result.data.\*.data.result_sets.\*.question_id | numeric |  `taniumrest question id`  |   58377 
action_result.data.\*.data.result_sets.\*.report_count | numeric |  |   2 
action_result.data.\*.data.result_sets.\*.row_count | numeric |  |   1 
action_result.data.\*.data.result_sets.\*.row_count_machines | numeric |  |   1 
action_result.data.\*.data.result_sets.\*.rows.\*.cid | numeric |  |   0 
action_result.data.\*.data.result_sets.\*.rows.\*.data.\*.text | string |  |   10.1.16.5 
action_result.data.\*.data.result_sets.\*.rows.\*.id | numeric |  |   1306085003 
action_result.data.\*.data.result_sets.\*.saved_question_id | numeric |  |   0 
action_result.data.\*.data.result_sets.\*.seconds_since_issued | numeric |  |   0 
action_result.data.\*.data.result_sets.\*.select_count | numeric |  |   1 
action_result.data.\*.data.result_sets.\*.tested | numeric |  |   1 
action_result.summary.number_of_rows | numeric |  |   3 
action_result.summary.timeout_seconds | numeric |  |   10 
action_result.message | string |  |   Number of rows: 3 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'get question results'
Return the results for an already asked question

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**question_id** |  required  | The ID of the question | numeric |  `taniumrest question id` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.question_id | numeric |  `taniumrest question id`  |   11111111 
action_result.data.\*.data.max_available_age | string |  |  
action_result.data.\*.data.now | string |  |   2019/07/24 07:53:06 GMT-0000 
action_result.data.\*.data.result_sets.\*.age | numeric |  |   0 
action_result.data.\*.data.result_sets.\*.archived_question_id | numeric |  |   0 
action_result.data.\*.data.result_sets.\*.cache_id | string |  |   2668614289 
action_result.data.\*.data.result_sets.\*.columns.\*.hash | numeric |  |   3112892791 
action_result.data.\*.data.result_sets.\*.columns.\*.name | string |  |   DNS Server 
action_result.data.\*.data.result_sets.\*.columns.\*.type | numeric |  |   5 
action_result.data.\*.data.result_sets.\*.error_count | numeric |  |   0 
action_result.data.\*.data.result_sets.\*.estimated_total | numeric |  |   2 
action_result.data.\*.data.result_sets.\*.expiration | numeric |  |   0 
action_result.data.\*.data.result_sets.\*.expire_seconds | numeric |  |   0 
action_result.data.\*.data.result_sets.\*.filtered_row_count | numeric |  |   1 
action_result.data.\*.data.result_sets.\*.filtered_row_count_machines | numeric |  |   1 
action_result.data.\*.data.result_sets.\*.id | numeric |  `taniumrest question id`  |   58377 
action_result.data.\*.data.result_sets.\*.issue_seconds | numeric |  |   0 
action_result.data.\*.data.result_sets.\*.item_count | numeric |  |   1 
action_result.data.\*.data.result_sets.\*.mr_passed | numeric |  |   1 
action_result.data.\*.data.result_sets.\*.mr_tested | numeric |  |   2 
action_result.data.\*.data.result_sets.\*.no_results_count | numeric |  |   0 
action_result.data.\*.data.result_sets.\*.passed | numeric |  |   1 
action_result.data.\*.data.result_sets.\*.question_id | numeric |  `taniumrest question id`  |   58377 
action_result.data.\*.data.result_sets.\*.report_count | numeric |  |   2 
action_result.data.\*.data.result_sets.\*.row_count | numeric |  |   1 
action_result.data.\*.data.result_sets.\*.row_count_machines | numeric |  |   1 
action_result.data.\*.data.result_sets.\*.rows.\*.cid | numeric |  |   0 
action_result.data.\*.data.result_sets.\*.rows.\*.data.\*.\*.text | string |  |   test 
action_result.data.\*.data.result_sets.\*.rows.\*.id | numeric |  |   1306085003 
action_result.data.\*.data.result_sets.\*.saved_question_id | numeric |  |   0 
action_result.data.\*.data.result_sets.\*.seconds_since_issued | numeric |  |   0 
action_result.data.\*.data.result_sets.\*.select_count | numeric |  |   1 
action_result.data.\*.data.result_sets.\*.tested | numeric |  |   1 
action_result.summary.number_of_rows | numeric |  |   3 
action_result.summary.timeout_seconds | numeric |  |   10 
action_result.message | string |  |   Number of rows: 3 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1 