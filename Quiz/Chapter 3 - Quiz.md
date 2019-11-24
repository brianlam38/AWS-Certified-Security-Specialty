# Which of the following statements is NOT correct in relation to CloudTrail?

```
It allows you to perform near real-time intrusion detection
It enables after-the-fact incident investigation
>>It prevents unauthorized users from accessing your account and launching AWS resources
It enables you to comply with industry and internal compliance requirements
```

# Which of the following tasks can you accomplish using CloudWatch? (Choose 3)

```
>>Resource utilization and monitoring
All of these are correct
>>Trigger Lambda functions
>>Log aggregation and analysis
Log all API calls in your AWS account
```

# You are looking for a security assessment tool to help improve the security and compliance in your environment by assessing your applications to check if they conform to best practices, which of the following should you use?

```
Amazon Guard Duty
AWS Config
AWS Trusted Advisor
>>Amazon Inspector
```

Amazon Inspector is an automated security assessment service that helps improve the security and compliance of applications deployed on AWS. Further information: https://aws.amazon.com/inspector/https://aws.amazon.com/config/https://aws.amazon.com/guardduty/https://aws.amazon.com/inspector/

# How can you make sure that your CloudTrail log files have not been modified, deleted, or changed?

```
Ensure your S3 bucket policy and IAM policies adhere to the Least Privilege model
Create a CloudWatch Event Rule to alert you of any modifications to the file
Encrypt your CloudTrail files using SSE:KMS
>>Use CloudTrail log Integrity Validation
```

To determine whether a log file was modified, deleted, or unchanged after CloudTrail delivered it, you can use CloudTrail log file integrity validation. Further information: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html

# You would like you be notified if any of the systems administrators in your organization creates a security group with SSH open to the world, which service allows you to easily do this?

```
>>Create a rule in AWS Config to notify you using SNS if this happens
Create a rule in CloudTrail to notify you if this happens
Create a rule in CloudWatch Logs to notify you if this happens
Create an SNS topic to notify you if this happens
```

Use AWS Config to evaluate the configuration settings of your AWS resources. You do this by creating AWS Config rules, which represent your ideal configuration settings. AWS Config uses Amazon SNS to deliver notifications to subscription endpoints. Further information: https://docs.aws.amazon.com/config/latest/developerguide/evaluate-config.htmlhttps://docs.aws.amazon.com/config/latest/developerguide/example-sns-notification.html

# Which of the following services can you use to view your asset inventory, check the configuration history for any given time and perform automated compliance checking?

```
CloudWatch
>>Config
CloudTrail
OpsWorks
```

# Which Amazon Inspector rules package would you use to check for instances which enable root login over SSH? (Choose 2)

```
Common Vulnerabilities and Exposures
Runtime Behaviour Analysis
>>Security Best Practices
>>Center For Internet Security Benchmarks
Network Reachability
```

Security Best Practices will report on instances which allow root login over SSH Further information: https://docs.aws.amazon.com/inspector/latest/userguide/inspector_security-best-practices.htmlhttps://docs.aws.amazon.com/inspector/latest/userguide/inspector_rule-packages.html

# How can you protect your CloudTrail logs from unauthorized access? (Choose 3)

```
>>Use IAM policies to restrict access to the S3 bucket containing the logs
>>Use S3 bucket policies to restrict access to the S3 bucket containing the logs
Compress the log files
>>Encrypt the log files
```

You can use AWS Identity and Access Management to control which AWS users can create, configure, or delete AWS CloudTrail trails, start and stop logging, and access the S3 buckets that contain log information. By default logs are encrypted using SSE-S3 or you can also configure encryption using SSE-KMS. Compressing the files will not protect them from unauthorized access. Further information:
https://docs.aws.amazon.com/awscloudtrail/latest/userguide/control-user-permissions-for-cloudtrail.html 
https://docs.aws.amazon.com/awscloudtrail/latest/userguide/encrypting-cloudtrail-log-files-with-aws-kms.html

# There are 3 key components to CloudWatch - CloudWatch monitoring, CloudWatch Logs and CloudWatch Events. What do these 3 different features of CloudWatch provide?

```
CloudWatch monitoring end-to-end network latency monitoring for web applications, CloudWatch Logs records all the API level events in your AWS account, CloudWatch Events responds to Lambda event triggers to perform automated tasks on your behalf.

CloudWatch monitoring provides intrusion detection and monitoring in your environment, CloudWatch Logs allows you to log security breaches in your applications and systems, CloudWatch Events provides a near real-time stream of security related events within your environment.

>>CloudWatch monitoring provides monitoring of performance metrics in your environment, CloudWatch Logs allows you to aggregate and monitor logs from your applications and systems, CloudWatch Events provides a near real-time stream of events within your AWS account which can be used to trigger actions such as triggering a Lambda function to perform a task.

CloudWatch monitoring provides monitoring of all user activity in your AWS account, CloudWatch Logs gives visibility of the network flows between application components in your environment, CloudWatch Events provides visibility of data center related events which could affect customers, like operating system upgrades and planned hardware maintenance.
```

CloudWatch collects monitoring and operational data in the form of logs, metrics, and events, providing you with a unified view of AWS resources, applications and services that run on AWS. Amazon CloudWatch Events delivers a near real-time stream of system events that describe changes in AWS resources. You can use Amazon CloudWatch Logs to monitor, store, and access your log files from Amazon Elastic Compute Cloud (Amazon EC2) instances, AWS CloudTrail, Route 53, and other sources. Further information: https://aws.amazon.com/cloudwatch/https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/WhatIsCloudWatchLogs.htmlhttps://docs.aws.amazon.com/AmazonCloudWatch/latest/events/WhatIsCloudWatchEvents.html

# You are looking for a tool which will assess your environment and provide Best Practice recommendations on each of the following areas: Cost Optimization, Performance, Security, Service Limits and Fault Tolerance. Which of the following should you use?

```
AWS Config
Amazon Inspector
Amazon Guard Duty
>>AWS Trusted Advisor
```

AWS Trusted Advisor is an online tool that provides you real time guidance to help you provision your resources following AWS best practices. Further information: https://aws.amazon.com/premiumsupport/technology/trusted-advisor/https://aws.amazon.com/inspector/https://aws.amazon.com/guardduty/https://aws.amazon.com/config/

# Which tool can you use to run a security check on your EC2 instances to check for common vulnerabilities and exposures?

```
Amazon Guard Duty
AWS Trusted Advisor
AWS Config
>>Amazon Inspector
```

# Which of the following services integrates with CloudTrail to send a notification to users that a log file has been created?

```
Simple Queue Service
>>Simple Notification Service
Simple Text Message Service
Lambda
```

You can configure a CloudTrail trail to use an Amazon SNS topic. CloudTrail will send an SNS notification when log files are written to the Amazon S3 bucket. An active account can generate a large number of notifications. If you subscribe with email or SMS, you can receive a large volume of messages. We recommend that you subscribe using Amazon Simple Queue Service (Amazon SQS), which lets you handle notifications programmatically. Further information: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/configure-cloudtrail-to-send-notifications.html