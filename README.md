
# Welcome to Purple Teaming with Detection-as-Code for Modern SIEM 
This guide will provide you with a step-by-step of all the commands we will use throughout this workshop. Please reference it as we move forward. If you have questions, feel free to ask your group moderator.


## Lab 1 - Writing Our First Detection
Using the rule function and other pre-existing helper functions, creating a detection is extremely efficient in Panther. For this exercise, you will use the Panther console to create your first detection. 

**Terms we'll reference**
- [All Available Rule Functions](https://github.com/panther-labs/panther-analysis/blob/master/templates/example_rule.py)
- [What is a rule?](https://docs.panther.com/writing-detections/rules)
- [What are Helpers?](https://docs.panther.com/writing-detections/globals?q=helpers)
- [What is Deep_Get?](https://docs.panther.com/writing-detections/globals#deep_get)

<details>
	<summary>Click To View: Sample Okta Event - Failed Login</summary>
  
```
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
</details>

**Lab 1: Exercise 1**
1. In the Panther Console - Navigate to Build > Detections > Create New
2. Select "Rule" and give it a unique name "[YOUR NAME]'s Failed Login Detection" 
3. Select the log source "Okta System Log" and set Severity to "Medium"
4. Select Functions and Tests in the tab
5. Create a Unit Test and copy and paste the sample event from Okta above. We will use this to create our detection. 
6. Import deep_get function from the panther_base_helpers library ```from panther_base_helpers import deep_get```
7. Return the event for a login ```return event.get("eventType") == 'user.session.start'```
8. Return the event for a failed login result using the deep_get function ```deep_get(event, 'outcome', 'result') == "FAILURE"```
9. Final detection should look something like this. 

```
from panther_base_helpers import deep_get

def rule(event):
    return event.get("eventType") == 'user.session.start' and deep_get(event, 'outcome', 'result') == "FAILURE"

```


10. Let's set a threshold for this alert in the "Rule Settings" tab , so we only get an alert triggered if there are 5 failed logins within a 15 minute interval.
![Threshold and depduplication](/img/depuplication.png)

**Lab 1: Exercise 2: Onboarding Okta Data**
1. [Sign up for a free Okta Developer](https://developer.okta.com/signup/) account if you have not done so.
2. In your Okta Developer acccount go to Security > API and click on the "Tokens" tab
![Okta Token Page](/img/okta1.png)
3. Click "Create Token" and give it a unique name
![Okta Token Page](/img/okta2.png)
4. Copy the new token and past it somehwere safe as backup
![Copy Token](/img/okta3a.png)
5. Go to your Panther free trial instance and navigate to Configure > Log Sources and search for "Okta"
![Panther Log Source Configure](/img/okta5.png)
6. Enter a name for the log source, your developer acccount subdomain and the API key we just created and click "Setup"
![Panther Log Source Configure](/img/okta6.png)
7. Congratulatsions you just onboarded your first data source! 

**Lab 1: Exercise 3: Enable Detection Packs**
1. Navigate to Build > Packs and search for "Okta"
2. Update and enable "Panther Okta Pack"
![Panther Okta Pack](/img/packs1.png)

## Lab 2 - Detected Admin Console Access & Scheduled Searches

**Lab 2: Exercise 1**
In this exercise we will write a new detection using what we have learned so far. If we look at the authenticaion logs there isn't any indicator the user is an administrator. However, once an admin logs in they are directed to the admin console which is logged as a seperate event. Log out of your Developer Okta instance and then back in. Go to Data Explorer and search for recent Okta event logs sorted in descending order. We will want to write a detection for when a user successfully logs into the admin console using what we have learned so far. Hint: Look for the eventType "user.session.access_admin_app." 

Extra points for using the ```def title(event) ``` function to add the admin name to the title. You should see an event that looks like this in Data Explorer, we will copy and past that JSON into the test field of our detection.

<details>
	<summary>Click To View Sample Data - Detect Successful Okta Admin Console Login </summary>

```
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
		"ziplyfiber.com"
	],
	"p_any_emails": [
		"lemmy@heavymetals.io"
	],
	"p_any_ip_addresses": [
		"50.39.221.8"
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
					"postalCode": "97224",
					"state": "Oregon"
				},
				"ip": "50.39.221.8",
				"version": "V4"
			}
		]
	},
	"securityContext": {
		"asNumber": 27017,
		"asOrg": "ziply fiber",
		"domain": "ziplyfiber.com",
		"isProxy": false,
		"isp": "ziply fiber"
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

<details>
	<summary>Click To View Answer - Detect Successful Okta Admin Console Login </summary>
  
```
from panther_base_helpers import deep_get

def rule(event):
    return event.get("eventType") == 'user.session.access_admin_app' and deep_get(event, 'outcome', 'result') == "SUCCESS"

def title(event):
    str_title=f"Okta Admin Console access by {deep_get(event,'actor','displayName')}"
    return str_title

```
</details>


**Lab 2: Exercise 2 - Scheduled Queries**

In addition to real-time detections, we can also look at data over a longer window of time via our Security Data Lake. Here we will create a scheduled query that looks specifically at a sequence of events leading to a successful brute force. The SQL statement has been provided to us by our threat hunting team. 


```
WITH
login_attempts AS ( -- filter for what we care about for speed
  SELECT
   p_event_time, 
   outcome:result AS outcome, 
   client:ipAddress AS clientIP, 
   client:userAgent.rawUserAgent AS userAgent, 
   actor
  FROM  panther_logs.public.okta_systemlog
  WHERE 
    outcome:result IN ('SUCCESS','FAIL','ALLOW','DENY')
    AND 
    p_occurs_since('60 minutes')
)

SELECT * from login_attempts
  MATCH_RECOGNIZE(
    PARTITION BY clientIP, userAgent, actor
    ORDER BY p_event_time DESC -- backwards in time
    MEASURES
      match_number() as match_number,
      first(p_event_time) as start_time,
      last(p_event_time) as end_time,
      count(*) as rows_in_sequence,
      count(row_with_success.*) as num_successes,
      count(row_with_fail.*) as num_fails
    ONE ROW PER MATCH
    AFTER MATCH SKIP TO LAST row_with_fail
    -- a success with fails following
    PATTERN(row_with_success row_with_fail+)
    DEFINE
      row_with_success AS outcome IN ('SUCCESS','ALLOW'),
      row_with_fail AS outcome IN ('FAIL','DENY')
  )
HAVING num_fails >= 8 -- how many fails must follow a success to qualify
ORDER BY clientIP, userAgent, actor, match_number
```



## Lab 3: Exercise 2 - Apply an out-of-the-box detection and modify it for your environment
By utilzing a pre-packaged detection, we can easily modify an existing detection to tune to our environment. By using the python functions that Panther provides, code templates are easily available. 

**Terms we'll reference**
- [What are Packs?](https://docs.panther.com/writing-detections/detection-packs)


**Exercise 1 Steps**
1. In the Panther Console - Navigate to Build > Packs > Okta Pack
2. Select the Okta.APIKey.Created rule
3. Duplicate your tab 
4. Navigate to Build > Detections > Create New and Create a new rule (Do not clone packed rule)
5. Name the detection a unique name with your initials - Sample "Okta API Key Created - Brandon"
6. Copy and Paste the code from Okta.APIKey.Created Packed Rule
7. Grab the severity function from the templates page or below 
```
def severity(event):
    if event.get("field") == "value":
        return "INFO"
    return "HIGH"
```
8. Add the severity function into your detection. Anywhere under the rule function is fine. 
9. Copy over the test event with the sample log event from Okta Sample Data Below
10. Modify the severity function to return a "Low" event when the user is your own email or otherwise return a "High" event (Hint - you will have to use deep_get for this)
11. Test your changes using the unit test
12. Save Changes


**Okta API Key Created Log Event**
```
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
		"alternateId": "user@example.com",
		"displayName": "Test User",
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

## Lab 4: Purple Teaming Detections

**Lab 4:  Exercise 1 - Installing Dorothy (Optional)**
Dorothy is a tool to help security teams test their monitoring and detection capabilities for their Okta environment [created by David French](https://github.com/elastic/dorothy) [@threatpunter](https://twitter.com/threatpunter) at Elastic Security. 
<br>
Note: Dorothy does not use exploits or conduct any brute force, the tool requires an Okta access token.
DO NOT TEST THIS TOOL ON A PRODUCTION OKTA INSTANCE, PLEASE USE [YOUR OKTA DEVELOPER ACCOUNT](https://developer.okta.com/)   

Requirements: Python 3.7+, pip3 
1. Installing Dorothy 

* Option 1: Using pip3 by runnning ```pip3 install dorothy``` 
* Option 2: You can install [Dorothy from source code](https://github.com/elastic/dorothy) 

2. We will simulate the process of an attacker creating a new access token, go to your Okta developer instance and create a new access token, copy and paste it somewhere safe

![Okta Token Page](/img/dorothy_okta_key.png)

3. Now we will run Dorothy and configure a new profile, you will enter a description, the URL of your Okta dev instance, the access token you just created, you can store the token locally, do not store the logs in Elasticsearch.

![Okta Token Page](/img/dorothy1.png)

4. Once configured enter the command ```whoami``` to view the user and permissions tied to the access token, you should see that we have Super Administrator access. 

![Okta Token Page](/img/dorothy3.png)

5. We can list the available modules by entering the ```list-modules``` command 

![Okta Token Page](/img/dorothy2.png)

6. We will first create a new user first we go into the ```persistence ``` and then ```create-user```

![Okta Token Page](/img/dorothy4.png)


