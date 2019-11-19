# Logging and Monitoring

## AWS CloudTrail

AWS CloudTrail is a web service that records AWS API calls for your account and delivers log files to you.
* User interacts with AWS platform via. Console or API Call.
* CloudTrail logs all these interactions with AWS services (only API calls).
* CloudTrail will NOT log actions such as SSH/RDP into an EC2.

Enables:
* After-the-fact incident investigation
* Near-realtime intrusion detection
* Industry and regulatory compliance

Provides:
* Logs API call details (for supported services)

Supported services: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-aws-service-specific-topics.html
Un-supported services: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-unsupported-aws-services.html
CloudTrail limits: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/WhatIsCloudTrail-Limits.html

Log info:
* Metadata around API calls
* Identity of API caller
* Time of API call
* Source IP of API caller
* Request params
* Response returned by the service

Where? CloudTrail Event Logs:
* Sent to an S3 bucket
* You manage retention in S3
* Delivered every 5 minutes to S3 with up to 15 minute delay
* SNS notifications available - e.g. notify you if something happens
* Can aggregate across multiple regions
* Can aggregate across multiple accounts - good for non-repudiation. Bad actor can only destroy within account, not audit account.

Setup:
* CT enabled by default (only keeps 7-day audit trail), you will need to provision to have it for longer.
* Management Events: ALL READ/WRITE
* Data Events (s3 object activity): leave as default = not enabled
* Storage Location: create a new S3 bucket

Validating CT log file integrity:
* SHA-256 hash
* SHA-256 with RSA for digital signing
* Log files are delivered with a 'digest' file
* Digest files can be used to validate the integrity of the log file
* You can use the AWS CLI to perform validation.

## CloudTrail Log Protection

Log files are encrypted by default (AES-256) even if the bucket itself doesn't show encryption turned on.

CT logs must be secured because they contain valuable info to an attacker such as:
* Personally identifiable info such as usernames / team membership.
* Config information such as a DynamoDB table and key names may be stored.

How to stop unauthorised access?
* Use IAM policies
* Use S3 bucket policies to restrict access
* Use SSE-S3 or SSE-KMS to encrypt logs

How do we restrict access to only employees with a security responsibility?
* Place employees who have a security role into an IAM group with attached policies
* Two AWS-managed policies: AWSCloudTrailFullAccess (security role) and AWSCloudTrailReadOnly (auditor role)

How can we be notified that a log file has been created / validate integrity?
* Configure SNS ontifs and log file validation.
* Develop a solution to execute log validation usign the digest file.

How to prevent CT log files from being deleted?
* Using IAM and bucket policies
* Configure S3 MFA delete
* Validate that logs have not been deleted using log file validation

How to ensure that logs are retained for X years?
* By default, logs are kept indenfinitely
* Can use S3 Object Lifecycle Management to delete files after required period of time.
    * Go to S3 bucket -> Management Tab -> "Add lifecycle rule" button -> Configure bucket expiration
* OR move files to AWS Glacier for long-term storage.

## AWS CloudWatch

AWS CloudWatch is a monitoring service for AWS cloud resources and the applications you run on AWS.

Enables:
* Resource utilisation,. operational performance monitoring
* Log aggregation and basic analysis

Provides:
* Real-time monitoring iwthin AWS for resources and applications
* Hooks to event triggers

Key components:
1. CloudWatch
2. CloudWatch Logs
3. CloudWatch Events

CloudWatch:
* Real-time monitoring: standard monitoring (every 5 mins) / detailed monitoring (every 1 min)
* Metrics: CPU utilisation, network utilisation
* Alarms: CPU > 80%, trigger alarm
* Notifications: SNS notifications etc.
* Custom Metrics: pass / program custom metrics via. AWS API.

CloudWatch Logs:
* Pushed from some AWS services, including CloudTrail
* Pushed from your applicaiton/systems - kernel logs, application logs, web-server logs etc.
* Metrics from log entry matches
* Stored indefinitely (not user S3)

CloudWatch Events | scenario: user creating EC2 instance, resulting in auto-deletion via. CloudWatch Events
1. User performs API call (create EC2)
2. API call logged in CloudTrail S3 bucket
3. CloudTrail is configured as a CloudWatch Event Source, so API call is pushed to CloudWatch Events
4. CloudWatch Events pushes details of API call to an Event Target, such as an AWS Lambda
5. AWS Lambda deletes EC2 instance.

CloudWatch Events:
* Near real-time stream of system events
* Events:
    * AWS Resources state change
    * AWS CloudTrail (API Calls)
    * Custom events (e.g. HTTP 403 status in Apache web-server logs)
    * Scheduled events
* Rules: match incoming events and orute them to one or more targets
* Targets: Lambda, SNS topics. SQS queues, Kinesis Streams and more

## AWS Config

AWS Config is a fully managed service that provides you with an AWS resource inventorgy, configuration history and configuration change notifications to enable security and governance.

Enables: Compliance auditing, security analysis, resource tracking (what resource we're using where)
Provides: Configuration snapshots and log config changes of AWS resources, automated compliance checking

AWS Config needs to be deployed in each individual region. It doesn't automatically deploy in every region in your account.

How does it work:
1. AWS resource configuration change -> event fires off
2. AWS Config picks up event -> AWS Config logs event in S3 bucket
3. Event target = Lambda is triggered -> Managed or Custom rules (Lambda functions)
4. AWS Config will evaluate if configuration change has broken a rule
5. If rule is broken, AWS Config will trigger SNS notification and is sent to user

Terminology:
* _Configuration Items_: point-in-time attributes of resource
* _Configuration Snapshots_: collection of config items
* _Configuration Stream_: stream of changed items
* _Configuration History_: collection of config items for a resource over time
* _Configuration Recorder_: the configuration of AWS Config that records and stores config items (Config Recorder Role)

Recorder Setup:
* Logs config for account in region (per-region-basis)
* Stores in S3
* Notified of issues via. SNS

What we see:
* Resources Type, Resource ID
* Compliance checks:
    * Trigger:
        * periodic
        * configuration snapshot delivery (change in resource config -> trigger check)
    * Managed Rules: ~40 rules
* Timeline: configuration details, relationships, changes, CloudTrail events

Permissions needed for AWS Config - requires and IAM role with:
* ReadOnly permissions to the recorded resources
* Write access to S3 logging bucket
* Publish access to SNS

Restrict access to AWS Config:
* Users need to be authenticated with AWS and have appropriate permissions set via. IAM policies to gain acecss.
* Only Admins/Security needing to set up and manage Config require full acecss.
* Provide ReadOnly for Config day-to-day use e.g. analyse misconfigurations etc.

Monitoring Config:
* Use CloudTrail with Config to provide deeper insight into resources.
* Use CloudTrail to monitor access to Config - e.g. someone stopping Config Recorder would be monitored in CloudTrail.

AWS Config is a big part of the exam, so read the Config FAQ: https://aws.amazon.com/config/faq/

## Set up an alert if Root user logs in / pro-active alerting (will be tested in exam)

1. Log in AWS Console
2. Go to CloudTrail -> create Trail
3. Configure CloudTrail to send CloudTrail logs to CloudWatch logs
    * A role is required for CT to perform CloudWatch API calls. Two calls are performed:
    * `CreateLogStream`: Create a CloudWatch Logs log stream in the CloudWatch Logs log group you specify.
    * `PutLogEvents`: Deliver CloudTrail events to the CloudWatch Logs log stream.

