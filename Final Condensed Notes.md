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

S3 Cross-Region Replication (CRR): replicate objects across S3 buckets in different AWS regions
* __CRR replicates__: NEW objects (_encrypted with SSE-S3/SSE-KMS or unencrypted_), metadata, ACL updates, tags.
* __CRR CANNOT replicate__: objects before CRR, objects encrypted by SSE-C, objects which bucket owner does NOT have permissions, object deletes of a specific version.

S3 Bucket Cross-Region Replicate with Cross-Accounts:
* __Audit use-case__: (1) CT logs acct-XYZ (2) CRR turned on to replicate CT logs to acct-Audit (3) acct-XYZ can only replicate logs to acct-Audit but NOT read/write to acct-Audit.
* __Permissions__: IAM role must have permissions to replicate objects in the destination bucket.
* __CRR Config__: You can optionally direct S3 to change ownership of object replicates to the AWS account that owns the destination bucket.

S3 bucket access - via. CloudFront using Origin Access Identity (OAI)
* __CloudFront Origin Access Identity__ is a virtual identity used to give a CF distribution permission to fetch a private object from an S3 origin on behalf of end-users. All direct access by using S3 URLs will be denied.
* Steps to enable: (1) Create an OAI in CloudFront + turn on `Restrict Bucket Access` (2) Update S3 bucket permissions: turn on `Grant Read Permissions on Bucket` OR change permissions manually in S3 bucket to allow OAI access.
* OAI principal with bucket access should be `arn:aws:iam::cloudfront:user/CloudFront Origin Access Identity EAFXXXXXID`

S3 object access - via. Presigned-URL for a temporary access to objects
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
* __Cognito User Pools__ are for authentication. With a User Pool, your app users can sign-in through the User Pool OR federate through a 3rd-party identity provider (IdP).
	* __User Pool Attributes__ are pieces of info that help you identify individual users, such as _name, email, mobile_.
* __Cognito Identity Pools__ are for authorization. Use Identity Pools to authorize your users (sourced from User Pools, FB, Google etc.) to different AWS services. You can also generate temporary AWS credentials for unauthenticated users.
* __Access to API Gateway via. Cognito User Pools as authorizer__: You can use a Cognito User Pool to control access to your APIs in API Gateway as an alternative to IAM roles and policies or Lambda authorizers.
	1. Create a Cognito User Pool -> Create an API Gateway authorizer w/ the chosen User Pool -> Enable the authorizer on selected API methods.
	2. User obtains an identity token from the User Pool after authentication, then the identity token is passed to the `Authorization` header in the API request.

Glacier Vault Lock: low-cost storage service for data archiving and long-term backup
* __Archives__ is a single file or multiple files stored in .tar/.zip.
* __Vault__ is a container which stores one or more archives.
* __Vault Lock Policy__ is used to configure __WRITE ONCE READ MANY (WORM)__ archives / create data retention policies.
* Vault Locking steps:
	1. CREATE Vault Lock Policy.
	2. INITIATE Vault Lock (`POST lock-policy`) -> attaches policy to your Vault -> 24hrs to validate policy, otherwise the policy is detached/removed from the Vault.
	3. TEST Vault Lock: ABORT Vault Lock (`DELETE lock-policy`) to detach policy and re-attach with INITIATE Vault Lock until you fine-tune the policy.
	4. COMPLETE Vault Lock (`POST lockId`) -> Vault is now locked and policy is UNCHAGEABLE/IMMUTABLE.
* Example Vault Lock Policy: enforce archive retention for 1 year:
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

__CloudTrail: validate Log File Integrity via. CLI__
* `$ aws cloudtrail validate-logs`

__CloudTrail: How do we stop unauthorised access to log files?__
* Use IAM policies and S3 bucket policies to restrict access to the S3 bucket containing the log files.
* Encrypt logs with SSE-S3 or SSE-KMS.

__CloudTrail: How can we be notified that a log file has been created, then validate that its not been modified?__
* Lambda to compare digest file of yesterday vs. digest of same file last week -> if digest is different, trigger SNS notification.

__CloudTrail: How can we prevent logs from being deleted?__
* Restrict access with IAM and bucket policies.
* Configure S3 MFA delete.
* Validate that logs have not been deleted via. log file validation.

__CloudTrail: How can we ensure logs are retained for X years in accordance with our compliance standards?__
* By default, log files are kept indefinitely.
* Use S3 Object Lifecycle Management to remove the files after the required period of time or move files to AWS Glacier for more cost-effective long-term storage.

__CloudTrail: Multi-region__
* Configure CloudTrail to deliver log files from multiple regions in a single AWS account into a single S3 bucket.
* New region launches in AWS partition -> CloudTrail automatically creates Trail in new region with same settings as your original trail.

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
* __AWS Config changes__: resource configuration changes -> AWS Config invokes `List`/`Describe` API call -> updating config is recorded as __Configuration Items__ and delivered in a __Configuration Stream__ to an S3 bucket.
* __AWS Config Rules__: resource config changes -> CloudWatch Event invokes custom/managed-rule's Lambda -> Lambda returns a compliance status.
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
* Rule packages allow you to run assessments related to a specific area:
	* __Network Reachability package__ help automate monitoring of AWS networks (VPS, ELBS) and identify where network access to your EC2 instances might be misconfigured.
	* __Common Vulnerabilities and Exposures__ help verify whether EC2 instances are exposed to CVEs.
	* __CIS benchmarks__ and __Amazon Inspector Security Best Practices__ rules.

AWS Trusted Advisor (advises on cost, performance, security, fault tolerance). Example security checks:
* __Security Groups__ for unrestricted access on specific ports (SSH inbound 0.0.0.0/0), overly permissive RDS SG access.
* __Credentials__: MFA on Root, IAM password policy, IAM key rotation, exposed access keys on the internet.
* __S3__: open access to S3 buckets.
* __Logging__: CloudTrail enabled

__S3 storage for logs__: best service for log storage
* S3 Object Lifecycle Management.
* 99.99% durability and 99.99% availability of objects over a given year.


## Chapter 4 - Infrastructure Security

KMS Customer Master Keys (CMKs): a master key, used to generate/encrypt/decrypt data keys
* __Data Keys__ are used to encrypt your actual data = __Envelope Encryption__.
* __7-30 day waiting period__ before you can delete CMKs.
* CMK administrative actions: `CreateKey, EnableKey, DescribeKey (get CMK metadata)` and more.
* CMK cryptographic operations: `Encrypt, Decrypt, GenerateDataKey (create Data Key that is encrypted with a specified CMK)`.

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
* You CANNOT enable _automatic key rotation_ for a CMK w/ imported Key Material (also applies to asymmetric CMKs and custom key stores backed by CloudHSM).
* You CAN _manually rotate_ by repeating process of creating a new CMK with new imported Key Material.
* You CAN delete imported keys immediately by deleting the Key Material.

KMS: key rotation options
* __AWS Owned CMKs__: AWS manages rotation | Rotation is varied - depends on the AWS service.
* __AWS Managed CMK__: AWS manages rotation | Rotation occurs every __3 YEARS__.
* __Customer Managed CMK__: Customer manages rotation | Automatic rotation every __1 YEAR__ can be enabled | Manual rotation is possible by deleting CMK + creating new CMK.
* __Customer Managed CMK w/ imported Key Material__: Customer manages rotation | NO automatic rotation | Manual rotation is only option by deleting CMK + creating new CMK.
* _Be careful of deleting OLD CMKs during rotation - KEEP the old key in case it is needed._

__KMS CMKs in Custom Key Store (backed by CloudHSM)__
* You can create CMKs in a custom key store, where KMS will generate and store key material for the CMK in a CloudHSM Cluster that you own and manage.
* Cryptographic operations are performed in the HSMs in the cluster.

__KMS CMKs with IAM policies__
* A Key Policy must explicitly allow IAM to use IAM policies to give users/roles access to the CMK.
* This is done by having an `ALLOW` statement for Principal `"AWS": "arn:aws:iam::111222333:root"` (Allow IAM in account 111222333 to use CMK).

__KMS Grants__ are used to programatically delegate TEMPORARY use of CMKs to other AWS principals.
* Grants only ALLOW, not deny access to a CMK.
* `create-grant` adds new grant to CMK, specifies who can use it and list of operations grantee can perform. A grant token is generated and can be passed as an argument to a KMS API.

__KMS Policy Conditions - ViaService__ is used to ALLOW/DENY access to your CMKs according to which service the request originated from.

__KMS Policy Conditions - `aws:SourceVpce`__ is used to enforce access to your CMKs to a specific VPC Endpoint e.g. "vpce-1234abcdf5678c90a" (VPC Endpoint ID).

__KMS CMK cross-account access__: enable access by
1. Change CMK Key Policy in origin account to allow a specific userARN/roleARN of destination account to have access.
2. Set up an IAM policy in destination account with explicit permission to use the CMK in the origin account.
3. Attach IAM policy to userARN/roleARN in destination account.

__KMS vs. CloudHSM__
* CloudHSM: Dedicated access to HSM that complies with government standards (FIPS) + you control keys and software that uses them (you need to do your own key management).
* KMS: Built on the strong protections of a HSM foundation, highly available/durable, auditable, easy integration with AWS services and applications.

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

AWS EC2 Hypervisor: is software, firmware, hardware that creates and runs virtual machines.
* __Hypervisor access by AWS employees__: Admins require MFA, access is logged/audited, administration hosts are specifically designed/built/configured/hardened to protect the management plane. Access is revoked upon no more business need for employee.
* __Memory scrubbing__:
	* EBS volumes are NOT scrubbed immediately after being deleted, only PRIOR TO BEING RE-USED.
	* Host (EC2) memory that is allocated is scrubbed/zeroed by the Hypervisor as soon as it is UNALLOCATED from the guest.
	* Host memory is not returned to the pool of free memory until scrubbing is complete.

* __AWS EC2 Hypervisor__: is software, firmware, hardware that creates and runs virtual machines. EC2 AMIs run on 2 types of virtualisation:
	* __Hardware Virtual Machine (HVM)__: VM guests are fully virtualised - they are not aware that they're sharing processing time with other VMs.
	* __Paravirtual (PV)__: (MORE LIGHTWEIGHT / QUICKER) VM guests relies on hypervisor to provide support for operations that normally require privileged access = guest OS has no elevated CPU access.
	* Hypervisor access by AWS employees is logged/audited + requires MFA + access strictly controlled. This cloud management plane is specially designed, built, configured and hardened.
	* Guest OS (EC2) instances are controlled completely by customers with full root over accounts, services and apps running on EC2. AWS has no right to access EC2s.
	* __AWS IS NOW SHIFTING ITS PHYSICAL SERVERS FROM XEN HYPERVISOR TO LINUX KERNEL-BASED VIRTUAL MACHINE (KVM) OPEN-SOURCE HYPERVISOR__.

Container security:
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

Amazon DNS - Default DHCP vs. Custom DHCP options
* __Default DHCP__ options set uses `AmazonProvidedDNS`. You cannot update the existing option set, only delete and create a new one.
* __Custom DHCP__ options set can be used by creating a NEW SET of DHCP options and providing IPs of up to 4 DNS servers.


## Chapter 5 - Data Protection With VPCs

__AWS Virtual Private Cloud (VPC)__ lets you provision a logically isolated section of the AWS cloud where you can launch resources in a virtual network that you define.

VPCs
* Flow of inbound traffic: entry via. __VPC Virtual Private Gateway (VPN)__ or __VPC Internet Gateway (public)__ -> Route Tables -> Network ACL -> Subnet -> Security Groups -> EC2s.
* __VPC Peering__ allows you to connect one VPC with another VPC via. direct network route using private IP addresses.
	* Peering is in a STAR CONFIGURATION i.e. 1 central VPC with 4 others. No TRANSITIVE PEERING is allowed.
* Setting up and testing a custom VPC:
	1. Create VPC -> provision private/public subnets to VPC -> provision Internet Gateway for public internet connectivity to VPC
	2. Create CUSTOM ROUTE TABLE -> add route to the internet `0.0.0.0/0` via. Internet Gateway -> disable internet access for MAIN ROUTE TABLE, so all new subnets created won't have internet access by default -> associate subnet with CUSTOM ROUTE TABLE
	3. Test internet connectivity using EC2s: Turn on `Auto-assign public IP addresses` for the public subnet so a public IPv4 address is assigned for all EC2s launched into the subnet -> try to SSH into EC2 in public subnet.

NAT Instances (OLD NAT METHOD)
* __Single instance reliance__: any crash = no internet access for servers in private subnet.
* __Limited network throughput__: amount of traffic supported depends on instance size.
* To have high availability, requires using Autoscaling Groups + multiple subnets in different AZs + scripts to automate failover (switching to a standby server upon failure).
* NAT instances can be used as a __Bastion Server__.

NAT Gateways (PREFERRED NAT METHOD)
* Scales automatically to 10GBps.
* Highly available, automatic failover.
* Security is managed by AWS - no need for Security Groups, server patching, antivirus protections etc.
* Automatically assigned with a public IP
* Create at least 1 NAT Gateway per Availability Zone so there is redundancy in case of Zone Failure.

NACLs vs. Security Groups
* __NACLs are STATELESS__: responses to allowed inbound traffic are subject to outbound rules (vice versa).
* __SGs are STATEFUL__: response to outbound requests will be allowed to flow in regardless of inbound security group rules (vice versa).
* __Default VPC NACL__ will ALLOW ALL traffic in/out of subnets associated with the VPC.
* __Custom NACLs__ created will by default DENY ALL traffic in/out.
* You can block specific IP addresses using NACLs, but not with Security Groups.

Elastic Load Balancers and TLS/SSL Termination: terminate at ELB vs. EC2
* __Terminate at Load Balancer__: ALB decrypts HTTPS request -> inspects headers -> routes request to EC2 as plaintext over local private network in your VPC.
	* __PRO: More resources + more cost-effective (USE ALB)__ as decryption is offloaded to ALB, allowing you to use smaller EC2 instances to handle application load.
	* __PRO: Reduces administrative overhead (USE ALB)__ as you don't need to manage X509 certs (used to decrypt/encrypt) individually on each EC2.
	* __CON: Unencrypted traffic (USE NLB OR CLB)__ between ALB and EC2 (however AWS states that EC2s that aren't part of the connection cannot listen in, even if they are running within your AWS account).
	* __CON: Compliance/regulatory requirements (USE NLB OR CLB)__ typically require use of E2E encryption.
* __Application Load Balancer (HTTP/HTTPS)__ only supports HTTPS termination using an SSL cert on the Load Balancer itself. Only supports HTTP/HTTPS connections.
* __Network Load Balancer (TCP, UDP, TLS)__ supports TLS/SSL termination on the Load Balancer AND EC2 instances. You will need to use TCP (load balancing at TCP transport-layer rather than HTTP application-layer).
* __Classic Load Balancer (TCP, SSL/TLS, HTTP, HTTPS)__ supports TLS/SSL termination on the Load Balancer AND EC2 instances.

VPC Flow Logs: enable you to capture info about IP traffic going to/from Elastic Network Interfaces (ENIs - represent a virtual networking card) in your VPC, stored in CloudWatch.
* Logs are created at 3 different levels: (1) VPC - captures all ENI traffic (2) Subnet - capture ENI and EC2 traffic within a particular subnet (3) Network Interface
* Cannot enable Flow Logs for VPCs that are peered with your VPC unless they're in the same AWS account.
* Cannot change configuration of Flow Logs after creation.
* Not all IP traffic is monitored: _EC2 metadata `169.254.169.254`_, _DHCP traffic_, _traffic to reserved AWS IPs_, _traffic generated by instances when they contact the AWS DNS server_.

How to build a highly available Bastion instance:
* __High availability__: at least 2x Bastion instances in 2 public subnets in 2 Availability Zones.
* __Autoscaling Groups__: minimum of 1 Bastion -> if Bastion goes down, ASG deploys a Bastion into one AZ or another.
* __Route53 health check__: run health checks on Bastion server.

Session Manager in AWS Systems Manager: enables secure remote login to EC2 instances (alternative to RDP/SSH)
* __Session Manager is Secure__: TLS encryption, no Bastion required, no Security Groups needed, CloudTrail logging, keystroke logging sent to CloudWatch/S3.
* Setting up Session Manager in AWS Systems Manager:
	1. Create EC2 instance role (IAM) w/ permission to call Systems Manager -> launch EC2 with no SGs.
	2. Create CloudWatch Log Group for Session Manager `SM_LogGroup`.
	3. Configure Session Manager #1: `Systems Manager` -> `Session Manager` -> `Preferences` -> enter CloudWatch Log Group created.
	4. Configure Session Manager #2: select session logging options (1) Encrypt logs with KMS (2) Send logs to S3 bucket (3) Send logs to CloudWatch.
	5. Start a session: `Sessions` -> Start a session and select running EC2 -> launch web shell.

__AWS CloudHSM__ provides Hardware Security Modules (HSM) in a cluster - a collection of individual HSMs that AWS CloudHSM keeps in sync. Any tasks performed on one HSM, other HSMs in the cluster will be updated.
* CloudHSM user types:
	1. __Precrypto Officer (PRECO)__: default account with admin/pass creds -> upon setting password, you will be promoted to CO.
	2. __Crypto Officer (CO)__: performs user management e.g. create and delete users and change user passwords.
	3. __Crypto Users (CU)__: performs key management (_create/delete/import/export_) and cryptographic operations (_encr/decr/sign/verify_).
	4. __Appliance User (AU)__: performs cloning and synchronization operations. CloudHSM uses AU to sync HSMs. AU exists in all HSMs and has limited permissions.

__AWS Direct Connect (DX)__ enables you to establish a dedicated private connection from an _on-premise network/datacenter to 1+ VPCs in the same region_ to reduce network costs, increase throughput, provide more consistent network experience than internet-based connections.
* __DX + VPN (AWS Virtual Private Gateway endpoint)__: The VPN provides end-to-end encryption while AWS Direct Connect provides a reliable network with low latency and increased bandwidth.

__AWS Transit Gateway__ connects VPCs and on-premise datacenters/networks through a central hub. Acts as a cloud router.
* NOT using Transit Gateway
	* Each VPC requires VPN connection and config to the on-prem network.
	* VPCs require peering between each other. If hundreds of VPCs = difficult to manage, not scalable.
* USING Transit Gateway
	* __Highly scalable__: supports thousands of VPCs (hub-and-spoke architecture)
	* __Centralised__: Transit Gateway sits between all your VPCs and Datacentre, only needs to be configured once. Any VPC connected to Transit Gateway can communicate with every other connected VPC.
	* __Route Tables__: can be used to enforce which VPCs can communicate with each other.
	* __Secure__: communication between VPCs are done via. AWS private network. Inter-region traffic is supported.

__AWS VPC Endpoints__ enable you to privately connect (using __AWS PrivateLink__) your VPC to supported AWS services without needing a NAT Gateway (goes over private network).
* _MOST SECURE WAY TO ALLOW RESOURCES TO CONNECT TO OTHER AWS SERVICES, AS TRAFFIC NEVER LEAVES VPC_.
* EC2 instances in your VPC do NOT require public IPs to communicate with resources in supported VPC Endpoint services.
* Supported services include `S3, DynamoDB, SNS, ELBs, CloudFormation` and more.
* Restrict access to AWS resources to only specific VPC Endpoints by using `aws:sourceVpce: vpce-endpoint-id`. E.g. S3 Bucket Policy condition to access S3 bucket via. specific VPCE only.


## Chapter 6 - Incident Response and AWS in the Real World

__DDoS: Amplification / Reflection Attacks__: Attacker sends 3rd-party server a request using spoofed IP -> server responds with greater payload than inital request.

Minimising DDoS
1. __Minimise attack surface__: reduce internet accessible services/servers, use Bastion host, whitelist allowed IPs.
2. __Absorb attack by scaling__: scale horizontally (machines++) and vertically (compute++) = additional levels of redundancy and buys time to analyze the attack.
3. __Safeguard public-facing resources__: AWS WAF, CloudFront (Geo-blocking, S3 Origin Access Identity), Route53 (alias records to redirect traffic to CloudFront, ELB or other security tools + Private DNS to manage internal DNS names for DBs, webservers etc. without exposing info publically).
4. __Learn what normal behaviour looks like__: spot abnormalities, create alarms to alert for unusual behaviour, collect forensic data to understand attacks.
5. __Create a plan for attacks__: validate design of architecture, understand costs of resiliency, know who to contact when attack occurs.
6. __AWS Shield__: protects all AWS customers on ELB, CloudFront and Route53 against SYN/UDP floods, reflection attacks and other layer 3/4 DDoS attacks.
7. __AWS Shield Advanced__: enhanced protections, $3k/month, always-on flow-based monitoring of network/app traffic, 24/7 DDoS Response Team (DRT), AWS billing protection.

AWS Account compromised - what to do?
1. CHANGE `AWS account Root Password`.
2. ROTATE, then DELETE `Root and IAM user access keys`.
3. DELETE `IAM Users that have been potentially compromised`.
4. DELETE `AWS resources you didn't create`.

EC2 has been hacked - what to do?
1. Stop instances immediately.
2. Take a snapshot of EBS volume + terminate instnace.
3. Deploy a copy of the instance in an __isolated environment__ (isolated VPC, no internet access).
4. Access the instance using an __isolated forensic workstation__.
5. Read logs to figure out how they obtained access.

Leaked Github keys - what to do?
* __IAM User Credentials__: (1) De-activate IAM User Access Key (2) Create new User Access Key (3) Delete old User Access Key
* __Root User Credentials__: (1) Goto `My Security Credentials` -> `Access Keys` -> De-active Root User Access Key. (2) Create new Root User Access Key (3) Delete old Root User Access Key

__AWS Certificate Manager (ACM)__: provision a SSL cert for a domain name you have registered. SSL certs are autorenewed provided the domain name was purchased from Route53.
* __Requesting a SSL cert__: (1) Add domain name (2) Select domain validation methods DNS or EMAIL (3) If DNS validation, add the given CNAME record to Route53. _IF YOU REQUIRE HTTPS BETWEEN END-USERS <-> CF, CERTIFICATE CAN ONLY BE REQUESTED/IMPORTED ON US-EAST-1 IN ACM_
* __Auto-renew SSL/TLS certs__: ACM provides autorenewal for Amazon-issued SSL/TLS certs.
* __Manual-renew SSL/TLS certs__: Imported SSL/TLS certs OR certs associated with R53 private hosted zones must be manually renewed.
* __Use Amazon SSL cert with CloudFront__: Goto `CloudFront` -> select distribution -> edit settings to change default CloudFront SSL cert to the new custom SSL cert associated with your domian name.
* __Use Amazon SSL cert with EC2__: Goto `EC2` -> `Load Balancers` -> create a load balancer -> `choose a certificate from ACM`.

Configuring Security Policy with ELBs / CloudFront (SSL/TLS protocols and ciphers)
* __2016-08__ is the recommended Security Policy as it supports most ciphers.
* __ECDHE-* cipher__ is required to enable Perfect Forward  Secrecy.

API Gateway - Throttling and Caching
* __Steady-State Limit__: 10,000 req/sec
* __Burst Limit__: (max concurrent requests) 5,000 req across all APIs within an AWS account.
* __API Gateway Caching__: cache API endpoint response for a specified __TIME TO LIVE (TTL)__
	* TTL=300 (default) | TTL=3600 (max) | TTL=0 (cache disabled)

AWS Systems Manager - Run Command
* __Manage EC2s and on-premise systems__: automate admin tasks and adhoc config changes e.g. patching.
* __Using EC2 Run Command__: Create EC2 instance and role for SSM `EC2 role for Simple Systems Manager` -> Goto `SSM` -> `Run a command` -> choose a command document e.g. `Configure CloudWatch` -> select target instance and run.
* __SSM Agent__ needs to be installed AND __EC2 instance role with SSM permissions__ enabled for the Run Command to work.
* __Systems Manager Document__ defines the commands and parameters to be run.

Compliance Frameworks
* __ISO27001__: _establishing, implementing, operating, monitoring, reviewing, maintaining and improving documented Information Security Management System (ISMS)_ within the context of the organisation's overall business risks.
* __FedRAMP (Federal Risk and Authorization Management Platform)__: Government-wide program that provides a standardised approach to security assessment, authorisation, continuous monitoring for cloud products/services.
* __HIPAA (Federal Health Insurance Portability and Accountability Act of 1996)__: _lower cost of healthcare and ensure good data security around healthcare info_.
* __NIST (National Institute of Standards and Technology)__: A framework for improving critical infrastructure security for organisations.
* __PCI DSS (Payment Card Industry Data Security Standard)__: Policies and procedures to optimise security of credit/debit/cash card transactions and protect cardholders against misuse of personal info.
* __FIPS 140-2__: a U.S government computer security standard used to approve cryptograhic modules.
	* __AWS CloudHSM__ meets level 3. Rated from level 1 -> level 4 (highest).


## Chapter 7 - Additional Topics

Using Amazon Macie
* Macie can only monitor S3 buckets within the same region.
* Macie uses `AWSServiceRoleForAmazonMacie` which cover mainly permissions for CloudTrail (creating/reading logs) and S3 (creating/deleting buckets and objects)
* An S3 CloudTrail bucket will be created to capture all data events with Macie.

Using Amazon GuardDuty
* Takes 7-14 days to establish a baseline - "_what is normal behaviour in your account?_"
* 30 days free, then is charged off __quantity of CloudTrail events__ and __volume of DNS and VPC Flow Logs__.

AWS Secrets Manager
* __Store credentials__ for RDS, non-RDS databases (DynamoDB) and any other secrets as long as you can store them as a key-value pair (SSH keys, API keys).
* __Automatic secret rotation__ can be turned on, but make sure your app is not using hardcoded credentials + make sure it is retrieving credentials from Secrets Manager.
* __Deletion of secrets__ require a 7 day waiting period.
* __Secrets Manager vs. Parameter Store__: Parameter Store is for passwords, db strings, license codes, parameter values, config data. Values may be cleartext or encrypted (Secure String Parameter). No charge and is integrated with AWS Systems Manager.

Using AWS Simple Email Service (SES)
* Configure Security Group associated with EC2 to allow outbound to the SES SMTP endpoint.
* __Using SES__: if you have reached a Sending Limit, you can request to increase it via. AWS Support.
* __Using custom Mail Transmission software__: e.g. JavaMail. EC2 throttles traffic over the default SMTP `port 25`. You can bypass the throttle by using `port 587` or `port 2587`.

AWS Security Hub:
1. __Centralised dashboard__ for findings/alerts from key AWS security services.
2. __Automated compliance checks__ by evaluating AWS resources against PCI-DSS, CIS controls and AWS Foundational Security Best Practices.
* Integrates with _GuardDuty, Macie, Inspector, IAM Access Analyzer, Firewall Manager, 3rd-party marketplace tools, CloudWatch (trigger lambdas/SIEM/3rd-party tools)_.

Network packet inspection in AWS
* __Network Packet Inspection / Deep Packet Inspection__ involves inspecting a packet's headers and data.
	* Filters non-compliant protocols, viruses, spam, intrusions.
	* Takes action by blocking, re-routing or logging.
	* IDS/IPS combined with a traditional firewall.
* How to use: install 3rd-party solution for Network Packet Inspection via. AWS Marketplace.

IDS/IPS solution to protection AWS infrastructure from possible threats.
* Use 3rd-party solutions from AWS Marketplace.

Active Directory Federation with AWS: AWS enables federated sign-in to AWS using Active Directory credentials
* Great for companies with an existing Active Directory Domain + have corporate users who have AD accounts.
* __2-WAY TRUST__: establishing AD federation with AWS
	* In AWS, configure ADFS as the __Trusted Identity Provider__ = "_Trust ADFS to provide your users' identities_"
	* In ADFS, configure AWS as the __Trusted Relying Party__ = "_Trust AWS to consume your users' identities_"
* Using ADFS to sign-in to AWS Console:
	1. User logs into ADFS via. ADFS sign-in page + provide credentials.
	2. ADFS authenticates user against Active Directory.
	3. ADFS sends back authentication response to user in the form of a SAML token.
	4. User sends SAML token to AWS sign-in endpoint (choose / assume role page).
	5. AWS sign-in endpoint makes an `STS AssumeRoleWithSAML` request to get temporary creds to AWS -> STS returns temporary credentials.
	6. AWS sign-in endpoint redirects user to the AWS Console.

AWS Artifact: is a central resource for compliance and security related documents / information
* Demonstrate compliance to regulators, evaluate your own cloud architecture, assess effectiveness of internal controls.
* Download _ISO 1270001 certs, PCI-DSS docs, SOC reports_.


## Troubleshooting Scenarios

VPC Peering - connection issues between VPCs (Route Table, NACL/SG rules)
1. Verify that routes in __Routing Tables__ for ALL peered VPCs and configured correctly, so they know how to route traffic to each other.
2. Verify that an ALLOW rule exists in the __NACL table__ for the required traffic.
3. Verify that __Security Group rules__ allow traffic between the peered VPCs.
4. Verify using __VPC Flow Logs__.

VPC - no internet access
* Configure Routing Table to use either an __Internet Gateway__ or a __NAT Gateway__.

VPC - VPN connection not working
* Ensure Routing Table is routing traffic to your data center via. the __Virtual Private Gateway__.
* VPN traffic flow: VPC Virtual Private Gateway -> VPC Router -> Routing Table -> NACL -> Private Subnet -> SG -> EC2

CloudWatch Logs - Lambda / EC2 not logging to CloudWatch Logs
* Basic role permissions required to log to CloudWatch are: `CreateLogGroup`, `CreateLogStream` and `PutLogEvents`.
* EC2 requires a CloudWatch agent installed and running.
* Lambda's EXECUTION ROLE requires the above permissions.

CloudWatch Events / S3 Event - Event not invoking Lambda
* Add permissions in __Lambda Function Policy__ for Cloudwatch Events or S3 Events  to `invoke` your Lambda function.
* This applies to ANY services that can invoke Lambdas listed here: https://aws.amazon.com/blogs/architecture/understanding-the-different-ways-to-invoke-lambda-functions

CloudTrail Logging issues
* __CT Logging not working__: Check S3 bucket name, S3 Bucket Policy, S3 Access Control List.
* __CT Logging is expensive__: S3 Data Events record all object-level API activity. Lambda Data Events record all invoke-API operations.
* __Auditor can't access logs__: `AWSCloudTrailReadOnlyAccess` IAM Policy allows access to CloudTrail logs.

Troubleshooting Identity Federation - use the correct API for the job
* `sts:AssumeRole`: If authenticated by AWS, typically for cross-account delegation.
* `sts:AssumeRoleWithSAML`: If authenticated by a SAML IdP (Active Directory etc.).
* `sts:AssumeRoleWithWebIdentity`: If authenticated by a Web Identity Provider (Facebook,, Google etc.)

SMTP or AWS SES SMTP - timeout issues
* EC2 throttles SMTP `port 25` by default. Use `port 587` or `port 2587` which are unrestricted or request to remove email sending limitations.

Lambda - issues with Lambda not being invoked OR Lambda not accessing resource
* __Lambda executions not logged in CloudWatch Logs__: `CreateLogGroup`, `CreateLogStream` and `PutLogEvents` required in LAMBDA EXECUTION ROLE.
* __Lambda cannot perform an action__ e.g. write to S3, log to CloudWatch, Terminate Instances, use a CMK, use Secrets Manager
    * Check the LAMBDA EXECUTION ROLE allows the actions.
* __Lambda cannot be invoked by service__ e.g. CloudWatch Event invoking Lambda.
    * Check the LAMBDA FUNCTION POLICY allows the service.
* Remember that some services have their own resource-based policies which will impact access to the resource
    * E.g S3 Bucket Policy, KMS Key Policies etc.
* NOTE: _Lambda Execution Role_ defines what the Lambda fn can do.
* NOTE: _Function Policy_ defines which services can invoke the Lambda fn.

