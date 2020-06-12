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


## Troubleshooting Secure Network Infrastructure - VPC

Troubleshooting VPCs
* Check routing tables, Security Groups, NACLs.
    * _Public traffic -> Public subnets_: make sure routing table is routing internet traffic to the INTERNET GATEWAY.
        * FLOW: Internet traffic -> VPC Internet Gateway -> VPC Router -> Routing Table -> NACL -> Security Group -> Public subnet.
    * _VPN traffic -> Private subnets_: make sure routing table is routing any traffic to your own datacenter through the VIRTUAL PRIVATE.
        * FLOW: VPN traffic -> VPC Virtual Private Gateway -> VPC Router -> Routing Table -> NACL -> Security Group -> Private subnet.
    * Check that _Security Groups_ and _Network Access Control Lists_ are permitting the traffic.
* Internet access - NAT Gateway, Internet Gateway.
* Check VPC Flow Logs to view `ALLOW` or `DENY` messages.
    * `DENY` messages should give you a clue as to where the problem might be.

Exam tips
* NACLs are stateless: you need to configure both INBOUND and OUTBOUND rules.
* Security Groups deny by default, use NACL to explicitly deny.
* If you are peering 2 VPCs, remember to configure routing tables in both VPCs so they know how to route traffic to each other.
* Problems with internet access: make sure you have configured your Routing Tables correctly, to use either a NAT Gateway OR Internet Gateway.


## Troubleshooting Authentication & Authorization

Authentication & Authorization issues: "Giving users the ability to access resources they need to perform their job, no more and no less".

Common issues with Conflicting Policies
* AWS authZ/authN takes a least privilege approach: all actions are DENY BY DEFAULT. You need to EXPLICITLY ALLOW permissions for actions you want users to perform.
* Explicit deny will always override an allow.
* With multiple policies in play e.g. IAM Policy, S3 Bucket Policy, S3 ACL, Key Policy, an action is only allowed if NO METHOD EXPLICTLY DENIES and AT LEAST ONE METHOD EXPLICITLY ALLOWS access.
* If you are using AWS Organisations: check if there is a PERMISSIONS BOUNDARY preventing the action.

Conflicting Policy Example: S3 Bucket Policy allowing all S3 actions for IAM user `FAYE` on all S3 resources, conflicting with an IAM Policy.
```json
// S3 Bucket Policy for LOG S3 bucket
{
    "Version": "2012-10-17",
    "Statement": [
        "Effect":"Allow",
        "Action":"s3:*",
        "Principal": {
            "AWS": "arn:aws:iam::11223344:user/brian"
        },
        "Resource":"*"
    ]
}

// IAM Policy attached to user brian
{
    "Statement": [
        { 
            "Sid":"AllowS3AccessToMyOwnBucket",
            "Effect":"Allow",
            "Action":"s3:*",
            "Resource": [
                "arn:aws:s3::::mybucket/*"
            ]
        }
        // This DENY statement overrides ALLOW statement in the S3 Bucket Policy
        {
            "Sid":"DenyS3AccessToLogsBucket",
            "Effect":"Deny",
            "Action":"s3:*",
            "Resource": [
                "arn:aws:s3::::*log/*"
            ]
        }
    ]
}
```

Troubleshooting Identity Federation
* Use the correct API for the job
* Authenticated by a Web Identity Provider (Facebook etc.): `STS:AssumeRoleWithWebIdentity` API call.
* Authenticated by a SAML Compliant ID Provider (Active Directory etc.): `STS:AssumeRoleWithSAML` API call.
* Authenticated by AWS: `STS:AssumeRole` API call.

Read more about Policy Evaluation Logic (worth reading): https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html


## Troubleshooting Cross Account Access With STS:AssumeRole


## Troubleshooting Lambda Access


## Troubleshooting Access To CMKs in KMS
