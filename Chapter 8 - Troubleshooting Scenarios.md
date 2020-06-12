# Troubleshooting Scenarios

## Troubleshooting Monitoring & Alerting - CloudWatch

__Common issue: Does the IAM user/role or AWS Service have correct permissions to allow them to read/write?__

Example: Issue with IAM user to reading CloudWatch dashboard
* Policy to allow user to read dashboard
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "autoscaling:Describe*",   // view EC2 autoscaling
                "cloudwatch:Describe*",    // view CloudWatch metrics
                "cloudwatch:Get*",
                "cloudwatch:List*",
                "logs:Get*",               // view CloudWatch logs data
                "logs:Describe*",
                "sns:Get*",                // view alarm-related SNS data
                "sns:List*"
            ]
        }
    ]
}
```

Example: Issue with EC2 sending logs to CloudWatch
* Is the CloudWatch agent installed on EC2?
* Is the CloudWatch agent running on EC2?
* Does the instance role have permissions to write to CloudWatch Logs?

Example: Unauthorised user able to create EC2 instances -> CloudTrail Logs API calls -> Send Event into CloudWatch Events -> CloudWatch Event triggers Lambda -> Lambda terminates unauthorised instances.
* Check that CloudWatch Events has permission to invoke the event target (Lambda)
* Check the Lambda's `Execution Role` (IAM role associated with Lambda upon execution) has permissions to terminate EC2

Exam tips
* Always check that IAM users have the correct permissions to allow them to do what they need to do.
* CloudWatch Logs require an agent to be _installed_ AND _running_ on your EC2 instance.
* For CloudWatch Events, make sure the _Event Target_ (Lambda, SNS, SQS, Kinesis) has the correct permissions to take whatever action it needs to e.g. _does the Lambda execution role include permissions to terminate an EC2?_


## Lambda permissions

Lambda _Function Policy_: defines which AWS resources are allowed to invoke your function.
Lambda _Execution Role_: defines which AWS resources your Lambda function can access, and what actions can be taken against those AWS resources.


## Troubleshooting CloudTrail Logging

Common issue: _Logging not working_ (CloudTrail logs not appearing in S3)
* Is CloudTrail enabled?
* Have you provided the correct S3 bucket name?
* Is the S3 Bucket Policy / S3 Access Control List correct?


Common issue: _Added costs_
* S3 Data Events and Lambda Data Events are high volume / high cost.
    * Data  Events are NOT enabled by default.
    * S3 Data Events: record S3 object-level API activity (e.g `GetObject` and `PutObject`) for individual or ALL buckets.
    * Lambda Data Events: record invoke API operations for individual or ALL functions.

Common issue: _Auditor is not able to access logs_
* Does the Auditor's account read access to CloudTrail?
    * By default, normal IAM users don't have access to CloudTrail logs. Explicit access is needed.
    * `AWSCloudTrailReadOnlyAccess` IAM Policy will allow access to CloudTrail logs.


## Troubleshooting Secure Network Infrastructure


## Troubleshooting Authentication & Authorization


## Troubleshooting Cross Account Access With STS:AssumeRole


## Troubleshooting Lambda Access


## Troubleshooting Access To CMKs in KMS
