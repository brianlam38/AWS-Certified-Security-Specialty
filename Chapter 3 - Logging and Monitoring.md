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
* Rules: match incoming events and route them to one or more targets
* Targets: Lambda, SNS topics. SQS queues, Kinesis Streams and more

## AWS Config

AWS Config is a fully managed service that provides you with an AWS resource inventory, configuration history and configuration change notifications to enable security and governance.

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

Set up an alert if the Root user logs in and makes API calls
1. Turn on CloudTrail-CloudWatch logs integration
    * A role is required for CT to perform CloudWatch API calls. Two calls are performed:
    * `CreateLogStream`: Create a CloudWatch Logs log stream in the CloudWatch Logs log group you specify.
    * `PutLogEvents`: Deliver CloudTrail events to the CloudWatch Logs log stream.
2. Create a CloudWatch Metric Filter
3. Assign a metric
4. Create a Metric Alarm `{ $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent" }`
5. Test the alarm and receive an SNS notification
6. Look up the event and take corrective actions

## AWS Cloud Hardware Security Module (CloudHSM)

_This topic is not really examined - can mostly skip it._


AWS CloudHSM service helps meet corporate, contractual and regulatory compliance requiremetns for data security by using dedicated Hardware Security Module appliances within the AWS Cloud.


Enables: Control of data, evidence of control, meet tough compliance controls
Provides: Secure key storage (generate, store public/private keys), cryptographic operations, tamper-resistant Hardware Security Module

## AWS Inspector and AWS Trusted Advisor - examined

AWS Inspector
* Automated security assessment service that helps improve security/compliance of applications on AWS.
* After performing an assessment, AWS Inspector produces a detailed list of security findings prioritised by level of security.
* Findings can be reviewed directly or as part of a report available via. AWS Inspector or API.
* How does it work (scenario: assessment target is an EC2/prod-webserver)
    1. Create an assessment target
    2. Install agents on EC2 instances
    3. Create "Assessment Template"
    4. Perform an "Assessment Run"
    5. Review "Findings" against "Rules"
* Master template: Testing all rules - multiple rules packages over a 24 hour period
* Rule Packages: CVE's, CIS OS Config Benchmarks, Security Best Practices, Runtime Behaviour Analysis

AWS Trusted Advisor
* A service to advise you on Cost Optimisation, Performance, Security, Fault Tolerance.
    * _Basic Trusted Advisor_: Core checks and recommendations
    * _Full Trusted Advisor_: Business and Enterprise Companies only
* Some recommendations available to basic plan:
    * Security Groups (unrestricted ports), IAM use, MFA on Root, Service Limits (usage limits), exposed EBS snapshots etc.

## Logging

Understand the 4 logging services and their differences: _CloudTrail, CloudWatch, Config, VPC Flow Logs_

Resources: White-paper _Security at Scale: Logging in AWS_ https://d1.awsstatic.com/whitepapers/compliance/AWS_Security_at_Scale_Logging_in_AWS_Whitepaper.pdf

Control access to log files:
* Prevent unauthorised access (Authentication):
    * IAM users, groups, roles and policies
    * S3 bucket policies
    * MFA (IAM and S3 bucket policy level)
* Ensure role-based access (Authorization):
    * IAM users, groups, roles and policies
    * S3 bucket policies
* Alerts when logs are created or fail:
    * CloudTrail notifications
    * AWS Config rules
* Alerts are specific, but don't divulge detail:
    * CloudTrail SNS notifications only point to log file location, not show actual details.
* Log changes to system components:
    * AWS Config rules
    * CloudTrail
* Controls to prevent modification to logs:
    * IAM and S3 controls and policies
    * CloudTrail log file validation
    * CloudTrail log file encryption

Storage of log files:
* Logs are stored for at least 1 year
    * Store logs for an organisational-defined period of time
    * Store logs in real-time for resiliency
* S3
    * S3 Object Lifecycle Management
    * 99.99999% durability and 99.99% availability of objects over a given year
