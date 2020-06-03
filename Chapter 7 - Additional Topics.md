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


## Security Hub


## Network Packet Inspection


## Active Directory with AWS


## AWS Artifact


## Additional Resources for Exam Preparation


## Free Practice Questions


