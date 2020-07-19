# Security at Scale: Logging in AWS

## Control Access to Log Files

_The ability to view or modify your log data should be restricted to authorised users._


Configure IAM roles and S3 bucket policies to enforce read-only access to your log files.

Enable AWS MFA on S3 buckets that store CloudTrail logs.


## Obtain Alerts on Log File Creation and Misconfiguration

_Alerts must be sent for logging creation or misconfiguration_.

CloudTrail publishes notifications when logs are CREATED or FAIL/MISCONFIGURED to:
* An S3 bucket: notification is shown via. AWS Console.
* An SNS topic: notification is received via. SMS/email or other AWS services.


## Manage Changes to AWS Resources and Log Files

_Understanding, preventing changes and unauthorized access to log data is necessary for the integrity of your change management processes and for the ability to comply with internal, industry and regulatory requirements around change management_.


CloudTrail logs any AWS API calls made via. AWS Console, AWS CLI and AWS SDKs.

By default, API call log-files are encrypted using SSE-S3 and placed into your S3 bucket.

Modifications to log data can be controlled via. IAM and MFA to enforce read-only access to your S3 buckeet storing your CloudTrail log files.


## Storage of Log Files

_Industry standards and legal requirements may require that log files be stored for varying periods of  time._

With CloudTrail, you can:
* Store log-files in S3 for RESILIENCY as S3 is designed for 99.99% durability and 99.99% availability of objects over a given year.
* Aggregate log-files across all regions and multiple accounts to a single S3 bucket.
* Configure your desired EXPIRATION PERIOD on log files written to an S3 bucket.

By deafult, log-files are stored indefinitely.

Move your log-files to Amazon Glacier to save costs on long-term storage.


## Generate Customised Reporting of Log Data

_Gaining a CLEAR understanding of activities users have performed and changes made to your IT environment is important._


CloudTrail log-files can be input into industry leading log management and analysis solutions to perform analytics.

CloudTrail produces log-data from a single internal system clock by generating event timestamps in Coordinated Universal Time (UTC) consistent with the ISO 8601 Basic Time and Date format standard.

CloudTrail delivers API calls with detailed info such as
* Type, data and time, location, source/origin, outcome (including exceptions, faults and security-event informatio), affected resource (data, system etc.) and associated user.
* User identity, time of event, IP address of user, request parameters provided by user, response elements returned by service and optional error code and error message.
