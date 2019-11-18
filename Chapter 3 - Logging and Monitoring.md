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

How can we be notified that a log file has been created / validate integrity
* Configure SNS ontifs and log file validation.
* Develop a solution to execute log validation usign the digest file.

