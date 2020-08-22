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
        * FLOW: VPN traffic -> VPC Virtual Private Gateway -> VPC Router -> Routing Table -> NACL -> Private Subnet -> Security Group -> instance
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


## Troubleshooting Cross Account Access with STS:AssumeRole API

_This definitely comes up in the exam._

Example: Dev users ReadOnly access to a Prod S3 bucket (cross-account access).
1. Create Prod IAM Role with ReadOnly access to Prod S3 bucket.
2. Allow Dev IAM User to assume the above role via. Trusted Relationship statement.

Common issue: _Check external account (Dev account) has permission to call `STS:AssumeRole`_
```json
// Dev IAM Policy attached to Dev IAM User - assume Prod IAM Role
"Statement":[
    {
        "Effect": "Allow",
        "Action": "sts:AssumeRole",
        "Resource": "arn:aws:iam::PRODUCTION_ACCOUNT-ID:role/ROLE-NAME"
    }
]
```

Common issue: _Check the external account is trusted AND has permission to perform the action you are attempting - Prod Account, Role._
```json
// Prod IAM Role - Add Trusted Relationship statement / Configure Dev account as a Trusted Entity + give permission to perform the STS:AssumeRole action.
"Version": "2012-10-17",
"Statement":[
    {
        "Effect": "Allow",
        "Principal": {
            "AWS": [
                "arn:aws:iam::DEVELOPMENT_ACCOUNT-ID:root"
            ]
        },
        "Action": "sts:AssumeRole"
    }
]
```

Example: Cross-account KMS access.

Common issue: _Key Policy needs to trust external account_.
1. Go to Prod Account KMS -> your CMK which you want to allow external access.
2. Select "Other AWS Accounts" add AWS account ID.

Common issue: _External account needs IAM Policy allowing users to run specific API calls related to resource (CMK in this case)_
```json
// Dev IAM Policy
"Statement":[
    {
        "Sid": "AllowUseOfCMKInAccount444455556666",
        "Effect": "Allow",
        "Action":[
            "kms:Encrypt",
            "kms:Decrypt",
            "kms:DescribeKey"
        ],
        "Resource": "arn:aws:kms:us-west-2:444455556666:key/1a2b3c"
    }
]
```

Exam Tips:
* _For cross-account access to S3_:
    1. Check that the IAM Policy in EXTERNAL account (Dev) needs to allow the user to call `STS:AssumeRole`
    2. Check that the IAM Policy in TRUSTING account (Prod) needs to allow the action.
* _For cross-account access to KMS_:
    1. Check that you have configured the `Key Policy` to allow access to the EXTERNAL account in the TRUSTED account.
    2. Check that you have configured the IAM Policy in the EXTERNAL account to take KMS actions on the TRUSTED account.
* THE TWO MAIN IDEAS FOR CROSS-ACCOUNT ACCESS:
    1. Enable access within the TRUSTED account sharing the resource.
    2. IAM Policy in the EXTERNAL account, allowing actions by a role/user in the account. 


## Troubleshooting Lambda Access

Example: You want Lambda executions to be logged in CloudWatch.
Common issue: _Lambda require permissions to write to CloudWatch Logs_
* This is defined by the Lambda EXECUTION ROLE, similar to EC2 Service Role (NOT Function Policy).
* NOTE: _Lambda Execution Role_ defines what the Lambda fn can do.
* NOTE: _Function Policy_ defines which services can invoke the Lambda fn.

Example: You want a Lambda fn to access a RDS database
Common issue: _Lambda requires permissions to access Secrets Manager (RDS db credentials held there)_
* This is defined by the Lambda EXECUTION ROLE.

Example: You want CloudTrail to report certain type of Events into CloudWatch Events, then invoke Lambda
Common issue: _Does the Lambda Function Policy allow CloudWatch Events to invoke the Lambda?_

Exam tips:
* _Lambda cannot perform an action_
    * E.g. write to S3, log to CloudWatch, Terminate Instances, use a CMK, use Secrets Manager
    * Check the LAMBDA EXECUTION ROLE allows the actions.
* _Lambda cannot be invoked by service_
    * E.g. CloudWatch Event invoking Lambda fn.
    * Check the LAMBDA FUNCTION POLICY allows the service.
* Remember that some services have their own resource-based policies which will impact access to the resource
    * E.g S3 Bucket Policy, KMS Key Policies etc.


## Troubleshooting Access To CMKs in KMS

Example: Accessing a CMK in KMS
Common issue: _Check that IAM user, group or role has permissions for the action they are attempting_
*
Access to use KMS Customer Master Keys is defined by:
1. __IAM Policy__ attached to User, Group or Role.
    * Defines actions such as `kms:ListKeys`, `kms:Encrypt`, `kms:Decrypt`.
2. __CMK Key Policy__
    * Defines `Key Admins`, `Key Users`, `trusted external accounts`.
