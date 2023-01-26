# dac-purple-teaming-workshop

# Welcome to the Detections Workshop
This guide will provide you with a step-by-step of all the commands we will use throughout this workshop. Please reference it as we move forward. If you have questions, feel free to ask your group moderator.


## Lab 1 - Writing Our First Detection
Using the rule function and other pre-existing helper functions, creating a detection is extremely efficient in Panther. For this exercise, you will use the Panther console to create your first detection. 

**Terms we'll reference**
- [All Available Rule Functions](https://github.com/panther-labs/panther-analysis/blob/master/templates/example_rule.py)
- [What is a rule?](https://docs.panther.com/writing-detections/rules)
- [What are Helpers?](https://docs.panther.com/writing-detections/globals?q=helpers)
- [What is Deep_Get?](https://docs.panther.com/writing-detections/globals#deep_get)

**Exercise 1 Steps**
1. In the Panther Console - Navigate to Build > Detections > Create New
2. Select "Rule" and give it a unique name "X's Failed Login Detection" (Use your own name or initials)
3. Select the log source "Okta System Log" and set Severity to "Medium"
4. Select Functions and Tests in the tab
5. Create a Unit Test and copy and paste the sample event from Okta below. We will use this to create our detection. 
6. Import deep_get function from the panther_base_helpers library ```from panther_base_helpers import deep_get```
7. Return the event for a login ```return event.get("eventType") == 'user.session.start'```
8. Return the event for a failed login result using the deep_get function ```deep_get(event, 'outcome', 'result') == "FAILURE"```
9. Final detection should look something like this. 

```
from panther_base_helpers import deep_get

def rule(event):
    return event.get("eventType") == 'user.session.start' and deep_get(event, 'outcome', 'result') == "FAILURE"

```

**Sample Okta Event Failed Login**
```
{
	"actor": {
		"alternateId": "admin",
		"displayName": "unknown",
		"id": "unknown",
		"type": "User"
	},
	"client": {
		"ipAddress": "111.111.111.111"
	},
	"eventType": "user.session.start",
	"outcome": {
		"reason": "VERIFICATION_ERROR",
		"result": "FAILURE"
	},
	"p_event_time": "2021-06-04 09:59:53.650807",
	"p_log_type": "Okta.SystemLog",
	"p_parse_time": "2021-06-04 10:02:33.650807"
}
```



## Exercise 2 - Apply an out-of-the-box detection and modify it for your environment
By utilzing a pre-packaged detection, we can easily modify an existing detection to tune to our environment. By using the python functions that Panther provides, code templates are easily available. 

**Terms we'll reference**
- [What are Packs?](https://docs.panther.com/writing-detections/detection-packs)


**Exercise 2 Steps**
1. In the Panther Console - Navigate to Build > Packs > Okta Pack
2. Select the Okta.APIKey.Created rule
3. Duplicate your tab 
4. Navigate to Build > Detections > Create New and Create a new rule (Do not clone packed rule)
5. Name the detection a unique name with your initials - Sample "Okta API Key Created - Brandon"
6. Copy and Paste the code from Okta.APIKey.Created Packed Rule
7. Grab the severity function from the templates page or below 
```def severity(event):
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





