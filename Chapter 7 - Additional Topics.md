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



## GuardDuty


## Secrets Manager


## Simple Email Service (SES)


## Security Hub


## Network Packet Inspection


## Active Directory with AWS


## AWS Artifact


## Additional Resources for Exam Preparation


## Free Practice Questions


