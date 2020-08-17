# Additional Topics

## AWS Athena

Athena is an interactive query service, allowing you to query and analyse data in S3 using SQL.
* Serverless, pay per query / per TB scanned.
* No complex Extract/Transform/Load (ETL) processes.
* Works with structured, semi-structured, unstructured data and many files types such as .csv .json.

What can Athena be used for?
* Run queries on log files stored in S3 e.g. ELB logs, S3 access logs, CloudTrail logs etc.
* Generate business reports on data stored in S3.
* Analyse AWS Cost and Usage reports.

Querying CloudTrail data stored in S3 using Athena
1. Create an empty database.
2. Create tables inside the database.
3. Example `cloudtrail_logs` table:
```sql
CREATE EXTERNAL TABLE cloudtrail_logs (
eventversion STRING,
useridentity STRUCT<
               type:STRING,
               principalid:STRING,
               arn:STRING,
               accountid:STRING,
               invokedby:STRING,
               accesskeyid:STRING,
               userName:STRING,
sessioncontext:STRUCT<
attributes:STRUCT<
               mfaauthenticated:STRING,
               creationdate:STRING>,
sessionissuer:STRUCT<  
               type:STRING,
               principalId:STRING,
               arn:STRING, 
               accountId:STRING,
               userName:STRING>>>,
eventtime STRING,
eventsource STRING,
eventname STRING,
awsregion STRING,
sourceipaddress STRING,
useragent STRING,
errorcode STRING,
errormessage STRING,
requestparameters STRING,
responseelements STRING,
additionaleventdata STRING,
requestid STRING,
eventid STRING,
resources ARRAY<STRUCT<
               ARN:STRING,
               accountId:STRING,
               type:STRING>>,
eventtype STRING,
apiversion STRING,
readonly STRING,
recipientaccountid STRING,
serviceeventdetails STRING,
sharedeventid STRING,
vpcendpointid STRING
)
ROW FORMAT SERDE 'com.amazon.emr.hive.serde.CloudTrailSerde'
STORED AS INPUTFORMAT 'com.amazon.emr.cloudtrail.CloudTrailInputFormat'
OUTPUTFORMAT 'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat'
LOCATION 's3://mycloudtrailbucket-faye/AWSLogs/757250003982/';
```

4. Now you can perform a query on the specified CloudTrail bucket using Athena:
```sql
SELECT
 useridentity.arn,
 eventname,
 sourceipaddress,
 eventtime
FROM cloudtrail_logs
LIMIT 100;
```


## Macie

Macie helps protect sensitive data (e.g. PII) in S3.
* Uses Machine Learning and Natural Language Processing (NLP) to discover, classify and protect sensitive data stored in S3.
* Includes dashboard visualisation, reporting and alerts.
* Great for PCI-DSS compliance and preventing identity theft.

Personally Identifiable Information (PII)
* Personal data used to establish an individual's identity.
* Exploited for identity theft and financial fraud.
* Includes: Home address, email address, SSN, Passport No., Drivers License, DOB, phone number, bank account number, credit card number.

How does Macie work? It classifies your data by four different domains:
1. By __Content Type__: JSON, PDF, Excel, TAR, ZIP, source code, XML.
2. By __Theme__: Amex, Visa, Mastercard credit card keywords, banking or financial keywords, hacker and web exploit words.
3. By __File Extension__: .bin .c .bat .exe .html .sql.
4. By __Regular Expression__: aws_secret_key, RSA Private Key, SWIFT Codes, Cisco Router Config.

How can Macie protect your data?
1. Analyse and classify data.
2. Dashboards, alerts and reports on the prescence of PII.
3. Gives visibility on how the data is being accessed.
4. Analyse CloudTrail logs and report on suspicious API activity.

Using Macie:
* Macie can only monitor S3 buckets within same region.
* Macie uses a service-role `AWSServiceRoleForAmazonMacie` which cover mainly permissions for CloudTrail (creating/reading logs) and S3 (creating/deleting buckets and objects).
* An S3 CloudTrail bucket will be created to capture all data events associated with Macie.
* Select AWS ACCOUNT ID to integrate Macie with -> Select ALL BUCKETS -> START CLASSIFICATION.
* Query S3 bucket/object properties to find PII / sensitive data.


## GuardDuty

GuardDuty is a threat detection service which uses Machine Learning to continuously monitor for malicious behaviour, such as:
* Unusual API calls, calls from a known malicious IP.
* Attempts to disable CloudTrail logging.
* Unauthorized deployments.
* Compromised EC2 instances.
* Recon by would-be attackers.
* Port scanning, failed logins.

Features:
* Alerts in GuardDuty console and to CloudWatch events.
* Receive feeds from 3rd-parties such as Crowdstrike and AWS Security, obtaining info about malicious domains / known IPs.
* Monitors CloudTrail Logs for all API activity, VPC Flow Logs, DNS Logs (by default all EC2s use AWS DNS - GuardDuty records all requests to/from AWS DNS from your EC2 instances)
* Centralise threat-detection across multiple AWS accounts.
* Automated response: GuardDuty detects compromised instance -> trigger CloudWatch Events -> trigger Lambda e.g. to isolate EC2 by updating security group + take snapshot.
* Machine Learning and anomoly detection.

Setup:
* Takes 7-14 days to establish a baseline - what is normal behaviour in your account?
* Once active, findings will appear on GuardDuty console and in CloudWatch ONLY if GuardDuty detects behaviour it considers a threat.
* 30 days free. Charged based on _quantity of CloudTrail events_ and _volume of DNS and VPC Flow Logs_.


## Secrets Manager

AWS Secrets Manager is a service which securely stores, encrypts and rotates DB credentials and other secrets.
* Encryption in-transit and at-rest using KMS.
* Automatically rotates credentials.
* Apply fine-grained access control using IAM policies.
* Your application makes an API call to Secrets Manager to retrieve the secret programatically.
* Reduces the risk of credentials being compromised.

What credentials can I store in secrets manager?
* RDS credentials (most common use-case)
* Credentials for non-RDS databases (e.g DynamoDB)
* Any other type of secrets, as long as you can store it as a _key:value pair_ (SSH keys, API keys)

Secrets Manager vs. Parameter Store
* Secrets Manager (mainly for DB credentials / keyvalue pairs)
    * Database credentials, API/SSH keys.
    * Built-in integration with RDS: MySQL, PostgreSQL, Aurora. 
    * Built-in rotation of RDS secrets, support for non-RDS using Lambda.
    * $0.40/secret per month | $0.05 per 10,000 API calls.
* Parameter Store
    * Passwords, database strings, license codes, parameter values, config data.
    * User-defined parameters.
    * Values may be cleartext or encrypted (Secure String Parameter).
    * No additional charge.
    * Integrated with AWS Systems Manager.

Secrets Manager - Automatic secrets rotation
* Setting: `Enable Automatic Rotation`
    * __WARNING: If you enable rotation, Secrets Manager immediately rotates the secret once to test the configuration. If your apps are using embedded (hardcoded) credentials, do not enable rotation as it will break your app__.
    * This is the recommended setting if your apps are NOT using embedded (hardcoded) credentials
* Setting: `Disable automatic rotation`
    * This is the recommended setting if your apps are using embedded (hardcoded) credentials.
    * Ensure that your apps are updated to retrieve credentials from Secrets Manager.

There is a 7-day minimum waiting period for deleting a secret.


## Simple Email Service (SES)

AWS Simple Email Service is a cloud-based email service, which supports both sending/receiving emails from your apps.
* Can be used to send marketing emails, transaction emails and email notifications from your apps.
* SES can be accessed using a standard SMTP (Simple Mail Transfer Protocol) interface OR via. the SES API, to allow you to integrate with existing applications.
* All connections to the SMTP endpoint must be encrypted in-transit using TLS.
* There are several different SMTP endpoints you can use when configuring connections into SES. See https://docs.aws.amazon.com/ses/latest/DeveloperGuide/smtp-connect.html.
    * Your EC2 instances will need to connect to these endpoints if it wants to send emails using SES.

Configuring Access to SES for EC2 instances
* Configure the Security Group associated with your EC2 instances to allow connections TO the SES SMTP endpoint.
* Default port is `port 25`, but _EC2 throttles email traffic over port 25_ (you can raise request to increase limit).
* However, avoid timeouts by using either `port 587` or `port 2587` instead.


## Security Hub

AWS Security Hub is
1. _A central hub for Security Alerts_: a single place to manage / aggregate findings and alerts from key AWS security services. Centralised dashboard.
2. _Automated checks_:
    * PCI-DSS (payment card industry)
    * CIS (Center for Internet Security)
3. _Ongoing security audit for all AWS accounts_

Security Hub integrates and with:
* GuardDuty (threat detection).
* Macie (PII and secrets in S3 buckets).
* Inspection (checks for CVEs).
* IAM Access Analyzer (scans IAM policies attached to resources that provide external access).
* AWS Firewall Manager (centrally manage WAF and SGs across multiple AWS accounts)
* External 3rd-party tools.
    * Pulling in findings from CheckPoint, F5, AlertLogic etc.
* CloudWatch (CloudWatch Events, to trigger a Lambda/SIEM/3rd-party system to take action).

Additional notes:
* Security Hub uses AWS Config for some CIS Benchmark checks (takes 12 hours from enabling AWS Config to notice changes).
* Takes time to pull info from GuardDuty / Inspector etc.


## Network Packet Inspection in AWS

__Network Packet Inspection__ involves inspecting packet headers and data content of the packet (known as DPI - Deep Packet Inspection).
* Filters non-compliant protocols, viruses, spam, intrusions.
* Takes action by blocking, re-routing or logging.
* IDS/IPS combined with a traditional firewall.

None of the following AWS services provide Network Packet Inspection
* VPC Flow Logs, AWS WAF, host-based firewalls like iptables and Windows Firewall.

What to do?
* Use a 3rd-party solution for Network Packet Inspections / IDS/IPS.
* Install 3rd-party software on your EC2 instance.
* Search the AWS Marketplace (Alert Logic, Trend Micro, McAfee) https://aws.amazon.com/marketplace.


## Active Directory Federation with AWS

AD Federation with AWS
* AWS allows federated sign-in to AWS using Active Directory credentials.
* Minimises the admin overhead by leveraging existing user accounts, passwords, password policies and groups.
* Provides SSO for users.
* _Great for companies that have an existing Active Directory Domain and you have corporate users who have AD accounts - you don't want to recreate those accounts in AWS._

Active Directory Terminology
* __ADFS (Active Directory Federation Services)__: Provides Single Sign-On (SSO) and acts as an Identity Broker between the Active Directory Domain in your data centre and AWS.
    * Runs directly inside your data centre.
* __SAML 2.0 (Security Assertion Markup Langauge)__: An open standard for exchanging identity and security information between identity providers and applications. Enables SSO for AWS accounts.
    * Allows users to use the AWS API and sign into AWS console using their corporate accounts.

Establishing AD Federation with AWS: __2-way trust__:
* Within AWS, you need to configure _ADFS = Trusted Identity Provider_.
    * "You need to tell AWS, to trust ADFS to provide your users' identities."
* Within ADFS, you need to configure _AWS = Trusted Relying Party_.
    * "You need to tell ADFS, to trust AWS to consume your users' identities."

Using ADFS to sign-in to AWS Console (after 2-way trust is configured0):
1. User logs into ADFS using a special ADFS sign-in webpage. They provide their company AD/corporate username and password.
2. ADFS will authenticate against the company Active Directory.
3. ADFS sends back authentication response in the form of a SAML token.
4. User's browser sends SAML token to AWS sign-in endpoint.
5. AWS sign-in endpoint makes an `STS AssumeRoleWithSAML` request to request temporary credentials to AWS console and STS returns temporary credentials.
6. AWS sign-in endpoint redirects user to the AWS console and the user will use temporary credentials to get access to the console.


## AWS Artifact

__AWS Artifact__ is a central resource for compliance and security related information.
* Download AWS security and compliance documents.
* ISO 127001 certifications, PCI-DSS docs, SOC (Service Organizational Control) reports.

AWS Artifact enables you to:
* Demonstrate compliance to regulators.
* Evaluate your own cloud architecture.
* Assess the effectiveness of your company's internal controls.
* _Example: if your company plans to launch a new credit card, AWS Artifact can help with the above_


## Additional Resources for Exam Preparation

AWS White Papers: https://aws.amazon.com/whitepapers
* There is a whole section dedicated to security.
* Important whitepapers to help pass Security Cert Exam: _KMS Best Practices, KMS Cryptographic Details, DDoS Best Practices, Logging in AWS, Well-Architected Framework - Security Pillar_
* Tip: Read the intro, the summary and choose the sections that you are weaker in (don't need to read the whole thing).

re:Invent Videos
* Great videos for exam prep
    * KMS Best Practices, AWS Encryption Deepdive, DDoS Best Practices
* Become an IAM Policy Master, VPC Fundamentals & Connectivity Options, Advanced Security Best Practices Masterclass.

Read FAQs on main security services.
* https://aws.amazon.com/faqs/
* Read all the FAQs under the _Security, Identity and Compliance_ heading.
* Best to focus on are KMS and IAM FAQs.


## Free Practice Questions

AWS Certification Quiz Shows
* Video with a focus on Security Specialty Exam.
* Explains how to approach the exam.
* Video 1: https://www.twitch.tv/aws/video/467770461
* Video 2: https://www.aws.training/Details/Video?id=37283
* Video 3: https://www.aws.training/Details/Video?id=37284
* Video 4: https://www.aws.training/Details/Video?id=37293

Other resources
* Mock exams in AWS Training ($20 each): semi-realistic questions to what you will see in the real exam.
* Free course: https://www.aws.training/Details/eLearning?id=49720

Other tips
* Do practise tests.
* Go through the explanation for BOTH incorrect and correct answers and study the AWS documentation associate with the answer to make sure you understand the subject well.