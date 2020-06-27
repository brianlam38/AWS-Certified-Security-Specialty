## Which of the following tools use machine learning to protect your data and resources in AWS? (Choose 2)

```
Athena
Inspector
>> Macie
>> GuardDuty
```

* Amazon Macie: uses machine learning to __discovery, classify and protect sensitive data__.
* Guard Duty: uses __machine learning, anomaly detection and integrated threat intelligence__ to __identify and priotize potential threats__ in your AWS environment.
* Athena: a query service that makes it easy to analyze data in S3 using SQL.
* Inspector: automated security assessment service to improve security and compliance of applications deployed on AWS.

## Your Chief Security Officer has asked you to monitor network requests and API calls coming from a set of malicious IP addresses. She would also like to receive a notification any time such activity is detected and create an automated work flow to quarantine any EC2 instances which is compromised. Which services would you recommend?

```
Use Trusted Advisor to report on threats and compromised instances, use CloudTrail and CloudWatch Events to trigger a Lambda function to terminate any compromised EC2 instances and send an SNS notification to alert the Security team via email
Use CloudTrail to detect malicious API activity, use AWS WAF to deny requests from malicious IP addresses, use VPC Flow Logs to report on requests coming from known malicious IP ranges, use CloudWatch events to trigger SNS notifications and a Lambda function to quarantine compromised instances
Use Inspector to detect exposure to malicious IP address ranges, use AWS WAF to deny malicious requests and use cloud formation and auto scaling groups to re-launch compromised instances
>> Use GuardDuty to detect threats and compromised instances, use CloudWatch Events to trigger SNS notifications and trigger a Lambda function to isolate any compromised EC2 instances
```

AWS GuardDuty is a __threat detection__ service that __countinuously monitors for malicious activity and unauthorised behaviour__.
* Analysis tens of billions of events across multiple AWS data sources, such as CloudTrail / VPC Flow Logs / DNS Logs.

## You would like to enable your users to access the AWS console and APIs using their on premises Active Directory credentials. Which of the following are valid configuration steps? (Choose 3)

```
Create corresponding IAM user accounts in AWS
>> Configure AD FS in your data center
>> Create an IAM role for each line of business or function and assign appropriate IAM policies
Configure a 2-Way trust between the on premises Active Directory environment and the Active Directory instance in your VPC
>> Configure a 2-Way Trust between AD and your AWS account
Configure a new Active Directory instance in your VPC
```

* AD FS authenticates the users against your Active Directory.
* A 2-Way trust is required between ADFS and AWS.
* You will also need to create roles with appropriate permissions attached, which federated users who have successfully signed-in will be allowed to assume.

## Which STS API call is used when a Active Directory federated user successfully accesses your AWS resources?

```
AssumeRole
>> AssumeRoleWithSAML
AssumeRoleWithWebIdentity
AssumeRoleWithADFS
```

__AssumeRoleWithSAML__ returns a set of temporary security credentials for users who have been authenticated via a SAML authentication response. This operation provides a mechanism for __tying an enterprise identity store or directory__ to __role-based AWS access__ without user-specific credentials or configuration.

## Which of the following network ports can be used to connect to the SES SMTP endpoint?

```
25, 285, 2785
>> 25, 587, 2587
25, 275, 2275
25, 875, 2875
```

* Port 25 is the default for SMTP, Amazon Amazon EC2 throttles email traffic over port 25 by default.
* To avoid timeouts when sending email through the SMTP endpoint from EC2, you can use port __587 or 2587__.

## Your Chief Security Officer has asked you to recommend tools which can perform Network Packet Inspection and IDS, what do you suggest?

```
Host based firewalls
>> Search for suitable tools on AWS MarketPlace
AWS WAF
VPC Flow Logs
```

__AWS does NOT provide any tools for Network Packet Inspection or IDS__, however there are plenty of tools available on the AWS Marketplace.

VPC Flow Logs helps you __capture info about IP traffic going to/from network interfaces in your VPC__ and can be published to __CloudWatch or S3__.
* You can diagnose overly restrictive security group rules.
* Monitor traffic reaching your EC2 instance.
* Determine direction of traffic to/from network interfaces.

## Your CEO asks you to provide documentary evidence to demonstrate that the AWS services you are using are PCI-DSS compliant. What do you suggest?

```
Contact the PCI Security Standards Council to request documentation
Carry out your own PCI-DSS assessment and document the outcome
>> Use AWS Artifact to download the relevant documentation
Tell your CEO to review the AWS Security Best Practices Whitepape
```

AWS Artifact is a __central resource for compliance-related information__. It provides on-demand access to AWS’ security and compliance reports and select online agreements, including SOC reports, Payment Card Industry (PCI) reports, and certifications from accreditation and compliance bodies.

## You would like to identify which of your files stored in S3 contain sensitive personal data like drivers licence numbers and social security numbers. Which AWS service will you use?

```
>> Macie
Polly
Athena
Guard Duty
```

Amazon Macie is a security service that uses machine learning to automatically discover, classify, and protect sensitive data in AWS. Amazon Macie recognizes sensitive data such as personally identifiable information (PII) or intellectual property, and provides you with dashboards and alerts that give visibility into how this data is being accessed or moved.

* AWS Polly: Text-to-speech service

## You would like run SQL queries on your CloudTrail logs, which of the following services can you use to achieve this?

```
RDS
Redshift
pgadmin
>> Athena
```

Amazon Athena is an interactive query service that makes it easy to __analyze data in Amazon S3 using standard SQL__. Using Athena with CloudTrail logs is a powerful way to enhance your analysis of AWS service activity.

## What is PII?

```
Personal IAM Information
Personal Information Inspection
Personal IoT Information
>> Personally Identifiable Information
```

PII is Personally Identifiable Information, like passport numbers, drivers licence number, home address, email address, credit card number, date of birth etc.

## You are planning to store the database credentials for your RDS PostgreSQL in Secrets Manager and would like to enable automatic rotation, how soon after enabling automatic rotation will the credential first be rotated?

```
According to the rotation interval that you selected
>> Immediately
After 24 hours
After 30 days
```

The first rotation will happen __immediately__, so you need to __make sure any applications which rely on this secret have been updated to retrieve it from Secrets Manager__ otherwise they will no longer be able to access the database.

## You would like to securely store RDS database credentials so that they are encrypted in transit and at rest and automatically rotated on a regular basis. Which tool should you use?

```
Systems Manager Parameter Store
S3 with SSE-S3
S3 with SSE-KMS
>> AWS Secrets Manager
```

AWS Secrets Manager is a secrets management service that helps you protect access to your applications, services, and IT resources. This service enables you to __easily rotate, manage, and retrieve database credentials, API keys, and other secrets throughout their lifecycle__.

__Parameter Store does NOT support auto rotation for RDS passwords__. Storing passwords on S3 is not recommended.