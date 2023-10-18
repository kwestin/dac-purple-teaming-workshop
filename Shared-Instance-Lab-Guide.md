
# Welcome to Purple Teaming with Detection-as-Code for Modern SIEM

This guide will provide you with a step-by-step of all the commands we will use throughout this workshop. Please reference it as we move forward. If you have questions, feel free to ask your group moderator.

## Lab 1 - Writing Our First Detection

Using the rule function and other pre-existing helper functions, creating a detection is extremely efficient in Panther. For this exercise, you will use the Panther console to create your first detection.

### Terms we'll reference

- [All Available Rule Functions](https://github.com/panther-labs/panther-analysis/blob/master/templates/example_rule.py)
- [What is a rule?](https://docs.panther.com/writing-detections/rules)
- [What are Helpers?](https://docs.panther.com/writing-detections/globals?q=helpers)
- [What is Deep_Get?](https://docs.panther.com/writing-detections/globals#deep_get)

Sample Okta Event - Failed Login:
  
``` json
{
 "actor": {
  "alternateId": "lemmy@heavymetals.io",
  "displayName": "Lemmy Kilmister",
  "id": "0u7gkf3fd41J4kku5d7",
  "type": "User"
 },
 "client": {
  "ipAddress": "111.111.111.111"
 },
 "eventType": "user.session.start",
 "outcome": {
  "reason": "INVALID_CREDENTIALS",
  "result": "FAILURE"
 },
 "p_event_time": "2023-01-23 09:59:53.650807",
 "p_log_type": "Okta.SystemLog",
 "p_parse_time": "2023-01:23 10:02:33.650807"
}
```

### Lab 1: Exercise 1

1. In the Panther Console, navigate to Build > Detections > Create New
2. Select "Rule"
3. Under Basic Info:
    - Provide a unique name. Example: "[YOUR NAME]'s Failed Login Detection"
    - Select the log type "Okta.SystemLog"
    - Set Severity to "Medium"
4. Feel free to add context (Description, Runbook, etc) under Rule Settings
5. Select "Functions & Tests":
    1. Under Rule Funtion write:
        - Import the deep_get function from the panther_base_helpers library `from panther_base_helpers import deep_get`
        - Return the event for a login and the event for a failed login result using the deep_get function `return event.get("eventType") == 'user.session.start' and deep_get(event, 'outcome', 'result') == "FAILURE"`
    2. Under Unit Test:
        - Create a Unit Test
        - Copy and paste the sample event from Okta above.
        - We will use this to _test_ our detection.
6. The final detection should look something like this:

    ``` python
    from panther_base_helpers import deep_get
    
    def rule(event):
        return event.get("eventType") == 'user.session.start' and deep_get(event, 'outcome', 'result') == "FAILURE"
    
    ```

7. Finally, let's improve this detection by setting a threshold for this alert in the "Optional Fields" menu , so we only get an alert triggered if there are 5 failed logins within a 15 minute interval.
![Threshold and depduplication](/img/depuplication.png)

___________________________________________________

## Lab 2 - Data Onboarding, Packs & Detected Admin Console Access

In this exercise, we will write a new detection using what we have learned. If we look at Okta's authentication logs, no indicator states that the user is an administrator. However, once an admin signs in, they are directed to the admin console, which Okta logs as a separate event.

Actions to perform:

1. The facilitator will log out of your Developer Okta instance and back in to generate data that will stream to Panther.
2. In the Panther Console, navigate to Investigate > Search and search for recent Okta event logs.
    - Database: panther_logs.public
    - Table: okta_systemlog
    - You should see an event that looks like this in Data Explorer, we will copy and past that JSON into the test field of our detection.

        <details>
            <summary> Sample Okta Event </summary>

        ``` json
        {
         "actor": {
          "alternateId": "lemmy@heavymetals.io",
          "displayName": "Lemmy Kilmster",
          "id": "00u84z2ve37HTBEAp5d7",
          "type": "User"
         },
         "authenticationContext": {
          "authenticationStep": 0,
          "externalSessionId": "102rfBoaRdTSyil1K5J-70qZw"
         },
         "client": {
          "device": "Computer",
          "geographicalContext": {
           "city": "Portland",
           "country": "United States",
           "geolocation": {
            "lat": 45.4085,
            "lon": -122.7981
           },
           "postalCode": "97224",
           "state": "Oregon"
          },
          "ipAddress": "50.39.221.8",
          "userAgent": {
           "browser": "CHROME",
           "os": "Mac OS X",
           "rawUserAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36"
          },
          "zone": "null"
         },
         "debugContext": {
          "debugData": {
           "dtHash": "01b9e25e49f63c515ec7d3d28541bc75dfe673c35931b96a7e90f433b524e2cb",
           "requestId": "Y91XUfm5OI--q_zkmcFZiQAACSQ",
           "requestUri": "/admin/sso/callback",
           "url": "/admin/sso/callback?code=******&state=32V3eK8pCBdtyxns6tRJ_BVWKuB7_oGy"
          }
         },
         "displayMessage": "User accessing Okta admin app",
         "eventType": "user.session.access_admin_app",
         "legacyEventType": "app.admin.sso.login.success",
         "outcome": {
          "result": "SUCCESS"
         },
         "p_any_domain_names": [
          ""
         ],
         "p_any_emails": [
          "lemmy@heavymetals.io"
         ],
         "p_any_ip_addresses": [
          ""
         ],
         "p_event_time": "2023-02-03 18:49:54.461",
         "p_log_type": "Okta.SystemLog",
         "p_parse_time": "2023-02-03 18:51:36.242",
         "p_row_id": "ead08fa06833fd8afdd5ed981604",
         "p_schema_version": 0,
         "p_source_id": "1cb8ad2c-a88c-4eff-b7b7-aa9473638728",
         "p_source_label": "WorkshopOkta",
         "p_timeline": "2023-02-03 18:49:54.461",
         "published": "2023-02-03 18:49:54.461",
         "request": {
          "ipChain": [
           {
            "geographicalContext": {
             "city": "Portland",
             "country": "United States",
             "geolocation": {
              "lat": 45.4085,
              "lon": -122.7981
             },
             "postalCode": "",
             "state": "Oregon"
            },
            "ip": "",
            "version": "V4"
           }
          ]
         },
         "securityContext": {
          "asNumber": 27017,
          "asOrg": "",
          "domain": "",
          "isProxy": false,
          "isp": "fiber"
         },
         "severity": "INFO",
         "target": [
          {
           "alternateId": "lemmy@heavymetals.io",
           "displayName": "Lemmy Kilmster",
           "id": "00u84z2ve37HTBEAp5d7",
           "type": "AppUser"
          }
         ],
         "transaction": {
          "detail": {},
          "id": "Y91XUfm5OI--q_zkmcFZiQAACSQ",
          "type": "WEB"
         },
         "uuid": "8c4d4d05-a3f3-11ed-8916-39bd47e0f0ef",
         "version": "0"
        }
        ```

        </details>

3. Finally, write a detection for when a user successfully logs into the admin console using what we have learned.
    - Hint: Look for the eventType "user.session.access_admin_app."
    - Extra points for using the `def title(event)` function to add the admin's name to the title.

    <details>
    	<summary>Click To View Answer - Detect Successful Okta Admin Console Login </summary>

    ``` python
    from panther_base_helpers import deep_get
    
    def rule(event):
        return event.get("eventType") == 'user.session.access_admin_app' and deep_get(event, 'outcome', 'result') == "SUCCESS"
    
    def title(event):
        str_title = f"Okta Admin Console access by {deep_get(event,'actor','displayName')}"
        return str_title
    
    ```

    </details>

___________________________________________________

## Lab 3: Exercise 2 - Modifying Existing Detections & Detecting API Key Creation

By utilzing a pre-packaged detection, we can easily modify an existing detection to tune to our environment. By using the python functions that Panther provides, code templates are easily available.

### Terms we'll reference

- [What are Packs?](https://docs.panther.com/writing-detections/detection-packs)


## Lab 3: Exercise 1

1. In the Panther Console, Navigate to Build > Packs > Okta Pack
2. Select the Okta.APIKey.Created rule
3. Open another tab and navigate to Build > Detections > Create New 
4. Name the detection with your name at the beginning - Sample " Lemmy Kilmster Okta API Key Created"
5. Copy the sample test data and code logic from the existing detection and paste it into the new detection you are creating
6. Grab the severity function from the [templates page](https://github.com/panther-labs/panther-analysis/blob/master/templates/example_rule.py) or below:

    ``` python
    def severity(event):
        if event.get("field") == "value":
            return "INFO"
        return "HIGH"
    ```

6. Add the severity function into your detection anywhere under the rule function.
7. Copy the test event with the sample log event from Okta Sample Data Below

    <details>
    	<summary>Sample Okta log event</summary>

    ``` json
    {
     "debugContext": {},
     "published": "2021-01-08 21:28:34.875",
     "eventType": "system.api_token.create",
     "version": "0",
     "legacyEventType": "api.token.create",
     "outcome": {
      "result": "SUCCESS"
     },
     "request": {},
     "uuid": "2a992f80-d1ad-4f62-900e-8c68bb72a21b",
     "severity": "INFO",
     "displayMessage": "Create API token",
     "actor": {
      "alternateId": "lemmy@heavymetals.io",
      "displayName": "Lemmy Kilmster",
      "id": "00u3q14ei6KUOm4Xi2p4",
      "type": "User"
     },
     "target": [
      {
       "id": "00Tpki36zlWjhjQ1u2p4",
       "type": "Token",
       "alternateId": "unknown",
       "displayName": "test_key",
       "details": null
      }
     ]
    }
    ```

    </details>

8. Modify the severity function to return a "Low" event when the user is your own email or otherwise return a "High" event (Hint - you will have to use deep_get for this)

    <details>
    	<summary>Click To View Answer</summary>

    ``` python
    def severity(event):
        if deep_get(event,"actor","alternateId") == "lemmy@heavymetals.io":
            return "LOW"
        return "HIGH"
    
    ```

    </details>

9. Test your changes using the unit test
10. Save Changes

___________________________________________________

## Lab 4: Purple Teaming Detections

The facilitator will run offensive operations against our Okta Developer account using Dorothy, this will generate attack data in our Security Data Lake that we will use to develop hypotheses for new detections. 



___________________________________________________

## Lab 4: Using Investigate and a Security Data Lake

1. Now let's go back to Panther and go to Search to see what data the activities in Dorothy generated, select the okta_systemlog table and click search. This will default sort to the most recent events first. We want to make sure we add the eventType field to our search results. 
    ![Query Builder ](/img/query_builder1.png)
2. In our results we should see some interesting events that indicate the creation of a new user as well as the escalation of that user's privileges.
  
3. Based on what we have learned let's explore these events and write a couple of new detections:
    - Write a detection that will trigger when a new user is created, include additional context such as the user(s) created.
    - Write a detection that will trigger when a user's permissions are escalated and include additional context regarding who did it and what accounts were affected.
    - Hints: look for these eventTypes `user.account.privilege.grant` and `user.lifecycle.create`

    <details>
    	<summary>Click to view answer for accounts created </summary>

    ``` python
  
    from panther_base_helpers import deep_get
    
    def rule(event):
        return event.get("eventType") == 'user.lifecycle.create' and deep_get(event, "outcome","result") == "SUCCESS"
    
    def title(event):
        return "New account(s) created by  " + deep_get(event,"actor","displayName")
    
    
    def get_display_names(event):
        rv = []
        target = event.get('target')
        for x in target:
            rv.append(x.get('displayName'))
        return rv
    
    def alert_context(event):
        return {"displayName": get_display_names(event)}
    ```

    </details>

    <details>
        <summary>Click to view answer for privilege escalation </summary>

    ``` python
    from panther_base_helpers import deep_get

    def rule(event):
        return event.get("eventType") == 'user.account.privilege.grant' and deep_get(event, "debugContext","debugData","privilegeGranted") == "Super administrator"

    def title(event):
        return "Privilege escalation by " + deep_get(event,"actor","displayName")
    
    def get_display_names(event):
        rv = []
        target = event.get('target')
        for x in target:
            rv.append(x.get('displayName'))
        return rv
    
    def alert_context(event):
        return {"displayName": get_display_names(event)}

    ```

    </details>
___________________________________________________

