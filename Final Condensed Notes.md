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

AWS Config: continuously monitors and records AWS resource configurations and allows you to automate evaluation of recorded configurations against desired configs.
* __Provides__: configuration snapshots, logs config changes of AWS resources, automated compliance checking.
* __Enables__: compliance auditing, security analysis, resource tracking (what resource we're using and where)
* How AWS Config works: resource configuration changes -> AWS Config invokes `List`/`Describe` API call -> updating config is recorded as __Configuration Items__ and delivered in a __Configuration Stream__ to an S3 bucket.
* How __AWS Config Rules__ work: resource configuration changes -> AWS invokes custom/managed-rule's Lambda -> Lambda returns a compliance status.
* __Use CloudTrail to gain deeper insights__: by getting an answer on _"Who made an API call to modify the configuration of this resource?"_

__Root User Monitoring via. CloudWatch__: setting up an alert for Root User API activity
1. Enable delivery of CloudTrail events to a CloudWatch Logs log-group.
	* A role is required for CT to perform CloudWatch API calls. Two calls are performed:
	* `CreateLogStream`: Create a CloudWatch Logs log-stream in the CloudWatch Logs log-group you specify.
	* `PutLogEvents`: Deliver CloudTrail events to the CloudWatch Logs logs-stream.
2. Select the CW log-group -> create a __CW Metric Filter__ (_defines terms/patterns to look for in log-data_) using filter: `{ $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent" }` -> assign Metric Filter "e.g. RootAccountUsage" to Metric "e.g. RootAccountUsageCount.
3. Create a __CW Alarm__: select Metric created above -> set a threshold level e.g.`THRESHOLD >= 1` -> set an action when an alarm-state occurs e.g. send SNS notification.

AWS Inspector: automated security assessment service to improve security/compliance of applications in your AWS account
* How it works: assessment performed -> prioritised findings produced -> findings can be reviewed directly or exported as a report via. Inspector or API
* __Assessment Template__ is a configuration you define your assessment run i.e. RULES PACKAGE to evaluate target with,DURATION of assessment, SNS TOPICS which Inspector sends notifications to about run-state/findings.
* __Rule packages__ include CVE's, CIS OS Config Benchmarks etc.

AWS Trusted Advisor: advise you on COST OPTIMISATION, PERFORMANCE, SECURITY, FAULT TOLERANCE
* Example security recommendations: service/usage limits, security groups (unrestricted ports), no-MFA on Root, exposed EBS snapshots etc.

__S3 storage for logs__: best service for log storage
* S3 Object Lifecycle Management.
* 99.99% durability and 99.99% availability of objects over a given year.


## Chapter 4 - Infrastructure Security

KMS Customer Master Keys (CMKs): a master key, used to generate/encrypt/decrypt data keys
* __Data Keys__ are used to encrypt your actual data = __Envelope Encryption__.
* __7-30 day waiting period__ before you can delete CMKs.

KMS: Create a Customer-managed CMK with imported key material
1. Create symmetric CMK with NO key material - select ORIGIN = EXTERNAL (non-AWS generated).
2. Download an AWS __Wrapping Key__ (public key) as `PublicKey.bin` and an Import Token `ImportTokenXXX`.
3. Use `openssl` to generate your own key material
```bash
# generates random 32 bytes (256 bits) + store in "PlaintextKeyMaterial.bin"
$ openssl rand -out PlaintextKeyMaterial.bin 32
```
4. Encrypt the key material with the Wrapping Key (public key):
```bash
# Encrypt the data in "PlaintextKeyMaterial.bin" using RSA key "PublicKey.bin"
# Resuting output as "EncryptedKeyMaterial.bin" as DER key format
$ openssl rsautl -encrypt \
             -in PlaintextKeyMaterial.bin \
             -oaep \
             -inkey PublicKey.bin \
             -keyform DER \
             -pubin \
             -out EncryptedKeyMaterial.bin
```
5. Upload `EncryptedKeyMaterial.bin` and `ImportTokenXXX` to the customer-managed CMK.

KMS: Considerations of using imported Key Material
* You CANNOT use `EncryptedKeyMaterial` and `ImportTokenXXX` files twice - they are single use only.
* You CANNOT enable _automatic key rotation_ for a CMK w/ imported Key Material.
* You CAN _manually rotate_ by repeating process of creating a new CMK w/ imported Key Material.
* You CAN delete imported keys immediately by deleting the Key Material.

KMS: key rotation options
* __AWS Owned CMKs__: AWS manages rotation | Rotation is varied - depends on the AWS service.
* __AWS Managed CMK__: AWS manages rotation | Rotation occurs every __3 YEARS__.
* __Customer Managed CMK__: Customer manages rotation | Automatic rotation every __1 YEAR__ can be enabled | Manual rotation is possible by deleting CMK + creating new CMK.
* __Customer Managed CMK w/ imported Key Material__: Customer manages rotation | NO automatic rotation | Manual rotation is only option by deleting CMK + creating new CMK.

__KMS Grants__ are used to programatically delegate temporary use of CMKs to other AWS principals. Grants only ALLOW.
* `create-grant`: adds new grant to CMK, specifies who can use it and list of operations grantee can perform. A grant token is generated and can be passed as an argument to a KMS API.
* `list-grants`: lists grants for a CMK.
* `revoke-grant`: remove a grant from a CMK.

__KMS Policy Conditions - ViaService__ is used to ALLOW/DENY access to your CMK according to which service the request originated from.

__KMS CMK cross-account access__: enable access by
1. Change CMK Key Policy in origin account to allow a specific userARN/roleARN of destination account to have access.
2. Set up an IAM policy in destination account with explicit permission to use the CMK in the origin account.
3. Attach IAM policy to userARN/roleARN in destination account.

EC2 security
* Importing a customer-managed key pair for SSH access:
	1. Generate a private-key using RSA 2048bits and a public-key
	```bash
	$ openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048
	$ openssl rsa -pubout -in private_key.pem -out public_key.pem
	$ chmod 400 private_key.pem
	```
	2. Go to EC2 -> Import a Key Pair -> choose your public-key. Now you can provision an EC2 instance and select the public-key.
	3. SSH into EC2 using the private key.
	4. Add additional logins by generating a new asymmetric keypair (type=RSA) via. `$ ssh-keygen -t rsa` -> add public-key to `~/.ssh/authorized_keys` in the EC2 -> login using private-key.
* You CANNOT use KMS with SSH for EC2 as AWS is involved in generation of KMS keys.
* You CAN use CloudHSM with SSH for EC2 because you can EXPORT CloudHSM keys.
* __EC2 Dedicated Instances__: run in a VPC on hardware that's dedicated to a single customer. Dedicated instances may still share hardware with other non-dedicated instances from the same AWS account.
* __EC2 Dedicated Hosts__: same as above AND provides additional visibility and control over how instances are placed on a physical server + consistent deployment to same physical server each time + enables you to use existing server-bound licenses (e.g VMWare, Oracle which may require dedicated hosts) + allows you to address corporate and regulatory compliance.
* __AWS EC2 Hypervisor__: is software, firmware, hardware that creates and runs virtual machines. EC2 AMIs run on 2 types of virtualisation:
	* __Hardware Virtual Machine (HVM)__: VM guests are fully virtualised - they are not aware that they're sharing processing time with other VMs.
	* __Paravirtual (PV)__: (MORE LIGHTWEIGHT / QUICKER) VM guests relies on hypervisor to provide support for operations that normally require privileged access = guest OS has no elevated CPU access.
	* Hypervisor access by AWS employees is logged/audited + requires MFA + access strictly controlled. This cloud management plane is specially designed, built, configured and hardened.
	* Guest OS (EC2) instances are controlled completely by customers with full root over accounts, services and apps running on EC2. AWS has no right to access EC2s.
	* __AWS IS NOW SHIFTING ITS PHYSICAL SERVERS FROM XEN HYPERVISOR TO LINUX KERNEL-BASED VIRTUAL MACHINE (KVM) OPEN-SOURCE HYPERVISOR__.

Container security principals:
1. __Don't store secrets__
	* Use IAM roles instead of hardcoding user credentials.
	* Use Secrets Manager for RDS credentials and API keys.
	* Use Amazon Certificate Manager (ACM) if you have TLS certs to store and manage.
2. __Don't run container as AWS root__
	* Don't run containers using your AWS Root account.
3. __Less is more__
	* Minimise attack surface by running one service per container, not multiple per container.
	* Avoid unnecessary libraries: remove code/libraries you don't need in your container image.
4. __Use trusted images only__
	* Avoid public repos, where you don't know the origin of code.
	* Use images from a trusted source or ones created inhouse.
	* Scan for CVEs using Amazon Inspector or external tools.
	* __AWS Elastic Container Registry (ECR)__ to store your own container images and use __AWS Elastic Container Service (ECS)__ to run containers.
5. __Infrastructure security__
	* Avoid public internet by using __ECS Interface Endpoints__ (similar to VPC endpoints)
	* If using public internet, use TLS to secure end-to-end communication between end-users and your apps running in containers.
	* __Amazon Certificate Manager (ACM)__ can be used to provide single, central interface for storing and managing certificates. It integrates well with many AWS services.