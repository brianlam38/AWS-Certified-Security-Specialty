## Chapter 2 - IAM, S3 and Security

Resetting Root Users
* Create new root user password / strong password policy.
* Delete 2FA then re-enable 2FA.
* Delete Access Key ID, Secret Access Key.
* Check existing user accounts and delete if not legitimate.

S3 Bucket Policy / ACL / IAM conflicts:
* __Explicit Deny Overrides__: An EXPLICIT DENY will always override any ALLOW.
* __Policy Conflicts__: Whenever an AWS principal (user, group or role) issues a request to S3, the authorization decision depends on the union of all the IAM policies, S3 bucket policies and S3 ACLs that apply.
* __Policy Conflict flow__: (1) DENY by default (2) If policy has EXPLICIT DENY = DENY (3) If policy has ALLOW = ALLOW

S3 Cross-Region Replication (CRR)
* __CRR AUDIT account use case__: CloudTrail logs accounts XYZ -> turn on CRR to replicate CloudTrail logs to AUDIT -> XYZ can only replicate logs, but NOT read/write logs in audit.
* __CRR replicates__: new objects (_encrypted w/ SSE-S3 or SSE-KMS + unencrypted_), metadata, ACL updates, tags
* __CRR NOT replicate__: objects before CRR, objects encrypted by SSE-C, objects which bucket owner does NOT have permissions, object deletes of a specific version.

Secure S3 bucket access via. CloudFront Origin Access Identity
1. Goto CloudFront -> __Origins and Origin Groups__
2. Turn on __Restrict Bucket Access__ -> Create an __Origin Access Identity__
3. Turn on __Grant Read Permissions on Bucket__ to allow CloudFront OAI to perform `s3:GetObject` | Resulting Policy:
```javascript
{
	"Sid": "BucketAccessViaCloudFrontOnly",
	"Effect": "Allow",
	"Principal": {
		"AWS": "arn:aws:iam::cloudfront:user/CloudFront Origin Access Identity EAF5XXXXXXXXX"
		},
	"Action": "s3:GetObject",
	"Resource": "arn:aws:s3:::AWS-EXAMPLE-BUCKET/*"
}
```

Secure S3 object access via. Presigned-URL
* Presign URL with 300s expiry: `$ aws s3 presign s3://acloudgurupresigned/hello.txt --expires-in 300`
* URL example: https://acloudgurupresigned.s3.amazonaws.com/OBJECT.txt?AWSACcessKeyId=XXX&Expires=XXX&x-amz-security-token=XXX&Signature=XXX

AWS Security Token Service (STS)
* __Federation__ uses SAML to combine a list of users in one domain (e.g. AWS IAM) with a list of users in another domain (e.g. Active Directory, Facebook, Google etc.)
* __Identity Broker__ is the service that allows you to take an identity from A and federate it to B.
* __Identity Store / Identity Provider (IdP)__ is the service that stores identities e.g. Okta, AD, FB, Google.
* __Identities__ are the users in a service like AD, FB, Google.

AWS STS authentication steps:
1. __As the Identity/User__, authenticate against the __Identity Store / Provider__ (Okta, AD, FB, Google).
2. __As the Identity Broker__, authenticate against STS using __STS:GetFederationToken__.
3. __As the Application__, authenticate against AWS service to obtain access to the requested resource.

Web Identity Federation with Amazon Cognito:
* __Amazon Cognito__: An Identity Broker to connect a WebApp to users from Identity Store/Provider like Facebook.
* __Cognifo benefits__: No need for mobile app to embed AWS credentials locally on device + provides user with seamless experience.
* __Cognito User Pools__: A user directory within AWS that allows sign-up and sign-in to your WebApp via. Cognito.

Glacier Vault Lock: low-cost storage service for data archiving and long-term backup
* __Archives__ is a single file or multiple files stored in .tar/.zip.
* __Vault__ is a container which stores one or more archives.
* __Vault Lock Policy__ is used to configure __write-once-read-many__ archives / create data retention policies.
	* Vault Lock Policy creation: create policy -> initiate lock by attaching policy to your Vault (in-progress state) -> 24 hours to validate lock policy (you can abort within 24 hours) -> once validated, Vault Lock policy is immutable.
* _Example Vault Lock Policy: enforce archive retention for 1 year_
```javascript
{
	"Sid": "deny-based-on-archive-age",
	"Principal": "*",
	"Effect": "DENY",
	"Action": "DeleteArchive":,
	"Resource": [
		"arn:aws:glacier:us-west-2:XXXaccountidXXX:vaults/examplevault"
	],
	"Condition": {
		"NumericLessThan": {
			"glacier:ArchiveAgeInDays": "365",
		}
	}
}
```
* __Vault Access Policy__ is for implementing access control rather than a Lock Policy which is compliance-related.

AWS Organisations: Service Control Policies (SCPs)
* __Service Control Policy__ enables you to restrict, at the account-level, what services and actions the IAM Entities in those accounts can do.
* SCP never GRANTS permissions, only LIMITS permissions.

__IAM Credential Report__ is a CSV-formatted report which lists all users in accounts + status of their various credentials, including PASSWORDS, ACCESS KEYS, MFA devices (last used, rotated).
* Requires `iam:GenerateCredentialReport` and `iam:GetCredentialReport`.


## Chapter 3 - Logging and Monitoring

__CloudTrail Log File Integrity Validation__ when enabled:
1. CT creates a HASH for every log file that it delivers.
2. CT then creates a DIGEST FILE that references the log files for the LAST HOUR and contains a hash of each log file.
3. CT signs each DIGEST FILE using a private/public keypair (AWS-controlled) - uses SHA-256 and SHA-256 hashing w/ RSA for digital signing.
4. After delivery of digest file, you can use the PUBLIC KEY to validate the digest file.

__CloudTrail: How do we stop unauthorised access to log files?__
* Use IAM policies and S3 bucket policies to restrict access to the S3 bucket containing the log files.
* Encrypt logs with SSE-S3 or SSE-KMS.

__CloudTrail:How can we be notified that a log file has been created, then validate that its not been modified?__
* Lambda to compare digest file of yesterday vs. digest of same file last week -> if digest is different, trigger SNS notification.

__CloudTrail: How can we prevent logs from being deleted?__
* Restrict access with IAM and bucket policies.
* Configure S3 MFA delete.
* Validate that logs have not been deleted via. log file validation.

__CloudTrail: How can we ensure logs are retained for X years in accordance with our compliance standards?__
* By default, log files are kept indefinitely.
* Use S3 Object Lifecycle Management to remove the files after the required period of time or move files to AWS Glacier for more cost-effective long-term storage.

AWS CloudWatch: real-time monitoring for resources and applications (utilisation / operational performance)
* __CW Metrics / CW Custom Metrics__: CPU utilisation, network utilisation
* __CW Alarms__: CPU > 80% utilisation = trigger CW Alarm
* __Notifications__: SNS notifications
* __CW Logs__: monitor, store and access log files from AWS services (e.g. CloudTrail) or apps/systems (EC2 kernel logs, appserver logs). CW log retention = logs are stored indefinitely by default.
* __CW Events__: delivers near real-time stream of system events that describe changes in AWS resources.
	* EVENT: An event indicates AWS resource state change, CloudTrail API calls, custom-events (HTTP 403), scheduled-events.
	* RULE: A rule matches incoming events and route them to one or more targets.
	* TARGET: A target processes events. Targets include Lambda, SNS topics, SQS queues, Kinesis Streams and more.

AWS Config: 