# Identity Access Management, S3 & Security Policies

Understanding IAM inside-out is crucial to passing this course.

IAM provides:
* Centralised control of your AWS account
* Shared access to your AWS account
* Granular permissions
* Identity Federation (Active Directory, Facebook, Linkedin etc.)
* MFA
* Provide temporary access for users/devices and services where necessary.
* Allows you to set up your own password rotation policy
* Integrates with many AWS services
* Supports PCI DSS Compliance

Critical Terms:
* Users - end users
* Groups - collection of users under one set of permissions (apply one policy to group, users inherit policy)
* Roles - assign roles to AWS resources (e.g. EC2, Lambdas)
* Policies - document that defines permissions

IAM is global - users, groups, roles, policies are done on a global level, not region-specific.

IAM Permissions Boundary for IAM Entities (users/roles)
* A Permissions Boundary is using a managed policy to set the _maximum permissions_ that an identity-based policy can grant to an IAM entity.
* https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html
* https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_iam-condition-keys.html#ck_PermissionsBoundary


## IAM Root User Scenario

Scenario: You have have started as a sysadmin at a cloud-based company. Previous admin used only the root-user.

First thing to do = rotate everything
* Change password
* De-activate then re-activate MFA
* Delete Access Key ID / Secret Access Key (don't create new access keys via. root user)
* Verify and delete IAM users that are not-legitimate.

## IAM Policies

IAM policies specify what you are allowed to do with any AWS resource. You attach IAM policies to users, groups or roles.

Types of IAM policies:
* AWS Managed Policies
* Customer Managed Policies
* Inline Policies

AWS Managed Policies:
* Standalone policy created / administered by AWS, which occasionally changes.
* Managed policy AWS Administrator has access to IAM, whereas PowerUser does not.

Customer Managed Policies:
* Standalone policy that you administer in your own AWS account.

Inline Policies:
* Used if you want to maintain a strict one-to-one relationship between a policy and the principal entity that its applied to.
* E.g. you want to be sure that permissions in a policy are not unintentionally assigned to a principal other than the one that the policy is intended for.
* Inline policies don't show up in the exam much.

## S3 Bucket Policies

S3 bucket policies specify what actions are allowed ot denied on the bucket.
* They are attached only to S3 buckets.
* They are bucket-level only (not bucket object-level).

Why use S3 policy instead of IAM policy
* You want to grant cross-account access to your S3 environment, without using IAM roles.
* Your IAM policies reach the size limit (2kb for users, 5kb for groups, 10kb for roles). S3 supports bucket policies of up to 20kb.
* You prefer to keep access control policies in the S3 env.

S3 Policy best use case: management of individual S3 buckets
* Having a deny policy for a specific bucket is easier than creating an IAM policy that denies access to a specific bucekt, then rolling that out to every user in your organisation.
* Example scenario: bucket could contain everyone's performance reviews in it.

Use the "AWS Policy Generator" to generate a S3 bucket policy.

S3 Policy "EXPLICIT DENY" will always override an "ALLOW".

## S3 Object Access Control Lists (ACLs)

S3 ACLs are a legacy access control mechanism. AWS recommends sticking to IAM policies and S3 bucket policies.
However, S3 ACLs can be applied to individual objects/files as opposed to S3 bucekt policies.

S3 ACL use cases:
* If you nede fine grained permissions on individual files/objects.
* Reachign size limit of 20kb for S3 bucket policies.

Managing S3 object permissions
* Click on object itself -> permissions
* Applying S3 object policies to individual IAM users - possible but can only be done via. CLI or AWS API (not console).
* Add S3 object access for other AWS Accounts by adding Account ID.

Conflict policy example: IAM user policy denying all S3 read vs. S3 bucket with object open to the public.
* Even though an explicit DENY overrides all ALLOW policies... the user would still be able to access the object. WHY??? =>
* The user CAN access objects in the public bucket via. the public bucket link (as an anonymous user).
* The user CANNOT access objects in the public bucket via. opening the object within AWS console/CLI/API (as an AWS user).

EXAM: Best exam practise is by creating your own S3 Bucket Policies, S3 Object ACLs, IAM User Policies etc.

## Policy Conflicts (EXAM ESSENTIAL TOPIC)

What happens if an IAM policy conflicts with an S3 policy which conflicts with an S3 ACL?

Whenever an AWS principal (user, group or role) issues a request to S3, the authorization decision depends on the union of all the IAM policies, S3 bucket policies and S3 ACLs that apply.

Least-privilege:
* Decisions ALWAYS default to DENY.
* An explicit DENY ALWAYS trumps an ALLOW.
* So if you DENY access to something somewhere and then something else allows acecssm the DENY will override the ALLOW.

ACCESS DENIED EXAMPLES:
* IAM policy grants access to an object + S3 bucket policy denies access to object + no S3 ACL exists.
* No method specifies an ALLOW, request is denied by default.

ACCESS ALLOWED EXAMPLE:
* No method specifies a DENY + one or more methods specify an ALLOW.

Policy conflict flow:
1. Decision starts at DENY by default.
2. Any applicable policies?
    -> YES = CONTINUE
    -> NO = DENY (0 allow/deny)
3. Does a policy have an EXPLICIT DENY?
    -> YES = DENY
    -> NO = CONTINUE
4. Does a policy have an ALLOW?
    -> YES = ALLOW
    -> NO = DENY (0 allow/deny)

This flow will be examined heavily with scenarios containing 2-3 different policies.

## Forcing Encryption on S3

Use S3 bucket policy to enforce encryption - prevent read without SSL enabled:
```json
// If secure transport is false, DENY read.
// Alternative policy, if secure transport is true, ALLOW read.
"Sid":"PublicReadGetObject",
"Effect":"Deny",
"Principal":{
    "AWS":"*"
}
"Action":"s3:GetObject",
"Resource":"arn:aws:s3:::bucketname/*",
"Condition":{
    "Bool":{
        "aws:SecureTransport":false
    }
}
```

### Cross-Region Replication

Cross-region replication replicates objects from one region to another.
By default, this is done using SSL. You don't need to enable encryption.

You can replicate objects from a source bucket to only one destination bucket (1-1 relationship).
After S3 replicates an object, the object can't be replicated again.

Cross-Region Replication (CRR) requirements:
* Src/dest buckets must have versioning enabled.
* Src/dest buckets must be in different AWS regions.
* Amazon S3 must have permissions to replicate objects from src/dest bucket on your behalf. When you enable CRR for the first time, a role will be created for you + a customer-managed policy will be assigned.
* If src bucket owner also owns the object, the bucket owner has full permissions to replicate the object. If not, object owner must grant the bucket owner `READ`/`READ_ACP` permissions via. the object ACL.

CRR Cross Accounts:
* The IAM role must have permissions to replicate objects in the destination bucket.
* In CRR config, you can optionally direct AWS S3 to change ownership of object replicas to the AWS account that owns the destination bucket.
* GOOD USE-CASE: CloudTrail auditing - have CT log everything inside an AWS account, turn on CRR and replicate audit logs to another AWS account. The AWS account will only have permission to replicate the objects, but not read,edit,delete CT logs. So you have a separate AUDIT account that contains all log data which can't be touched.

Best-practice to have a separate AWS account, turn on Cross-Region Replication, have your CloudTrail logs replicated to an AWS "AUDIT ACCOUNT" and you can't go in and read, write, delete those logs.

What is replicated?
* New objects created after you add a replication config.
* S3 replicates objects encrypted using S3 managed keys (SSE-S3) or KMS managed keys (SSE-KMS) + unencrypted objects.
* Object metadata
* Object ACL updates
* Object tags
* S3 replicates only objects in the src bucket for which the bucket owner has permissions to read objects and read access control lists.

DELETE marker replication
* Delete markers on an object are replicated. Deleted versions of objects are NOT replicated.
* A delete marker only hides an object via. versioning, not actually delete it.

What is NOT replicated
* Anything created BEFORE CRR is turned on.
* Objects created with SSE using customer-provided (SSE-C) encryption keys.
* Objects created with SSE using AWS KMS-managed encryption (SSE-KMS) keys, unless you explicitly enable this option.
* Objects in the src bucket for which the bucket owner does NOT have permissions (happens when the obj owner is different from the bucket owner).
* Deletes to a particular VERSION of an object. This is a security mechanism. Stops being maliciously deleting versions of a file.

Resources:
* Cross-Region Replication: https://docs.aws.amazon.com/AmazonS3/latest/dev/replication.html
* What does S3 replicate: https://docs.aws.amazon.com/AmazonS3/latest/dev/replication-what-is-isnot-replicated.html

## Securing S3 Using CloudFront

Force users to only access S3 via. CloudFront instead of direct access via. S3 URL.

Steps to create a new CF distribution:
1. CloudFront service
2. Create a new distribution -> Web Distribution
3. Origin Domain Name: the source S3 bucket URL
4. Restrict Bucket Access -> NO (exam will test how to restrict AFTER a distribution has already been created)
5. Everything as default

Steps to secure the CF distribution:
1. CloudFront service
2. Select distribution -> Distribution Settings -> Origins -> Select Origin -> Edit
3. "Restrict Bucket Access" = YES. You need an "Origin Access Identity" - a special CF user (an origin access identity) to your origin.
4. "Grant Read Permissions on Bucket" = YES. So CF can update the bucket policy for you.

## Using SSL Certificates using CloudFront

DEFAULT SSL CERTIFICATE: If you have happy for users to access your content using *.cloudfront.net domain name.
CUSTOM SSL CERTIFICATE: If you want to use a domain name that you own example.com.

You must store your custom SSL Certificate using:
* IAM API
* AWS Certificate Manager (ACM)
* Only in the `us-east-1` region = US East (N. Virginia)

## Secure S3 Using Pre-Signed URLs

Another method of accessing objects inside S3 - done via. SDKs (Python, Java, Go) or CLI.

```bash
$ aws s3 mb s3://acloudgurupresigned                # Make bucket
$ echo "Hello Cloud Gurus" > hello.txt
$ aws s3 cp hello.txt s3://acloudgurupresigned      # Upload object to bucket
$ aws s3 ls s3://acloudgurupresigned                # Check object is in bucket
$ aws s3 presign s3://acloudgurupresigned/hello.txt --expires-in 300 # presign URL with 300 sec expiration (default expiry = 1 hr)
https://acloudgurupresigned.s3.amazonaws.com/hello.txt?AWSACcessKeyId=XXX&Expires=XXX&x-amz-security-token=XXX&Signature=XXX
```

## Security Token Service (STS) (IMPORTANT EXAM TOPIC)

STS grants users limited and temporary access to AWS resources.

These users can come from:
* Federation (typically Active Directory)
  * Uses SAML
  * Grants temp access based off user's AD credentials. Does not need to be a user in IAM.
  * SSO allows users to log into AWS console without assigning IAM credentials.
* Federation with Mobile Apps
  * Facebook / Amazon / Google or other OpenID providers.
* Cross Account Access
  * Lets users from one AWS account access resources in another.

Key Terms:
* Federation - combining or joining a list of users in one domain (such as IAM) with a list of users in another domain (such as AD, Facebook etc.)
* Identity Broker -  service that allows you to take an identity from point A and join it (federate it) to point B.
* Identity Store - services like AD, Facebook, Google etc.
* Identities - a user of a service like Facebook etc.

An Identity is a user, that is stored in an Identity Store (like Active Directory/Facebook). You create an Identity broker that allows you take those Identities in your Identity Store and join them up to IAM -> This is essentially the federation/joining of IAM with AD/Facebook. The service that allows this is the Security Token Service.

Scenario: _You are hosting a company website on EC2 web servers in your VPC. Users of the site must login to the site, which authenticates against the company's AD servers which are based on-site at the company HQ. Your VPC is connected to the company HQ via. a secure IPSEC VPN. Once logged in, the user can only have access to their own S3 bucket._

How to set this up:
1. Develop an Identity Broker (join AD -> IAM).
2. Identity Broker will authenticate (using client/appid, secret) against AD:
    * Authenticate to obtain an AD token.
    * Pass AD token to STS.
    * STS will provide us with another token.
3. Pass STS to the web application to authenticate against S3.
4. S3 uses IAM to check if user has access to S3.
5. User is able to access S3.

Scenario:
1. Employee enters username / password
2. Application calls Identity Broker. Broker captures username/password.
3. Identity Broker uses the organisation's LDAP directory to validate the employee's identity.
4. Identity Broker calls the GetFederationToken function using IAM credentials.
    * GetFederationToken(DurationSeconds, Name, Policy, PolicyArn) where:
    * _DurationSeconds_: duration of the STS token (1 to 36 hours).
    * _Name_: name of the federated user.
    * _Policy_: inline IAM policy.
    * _PolicyArn_: ARN referencing an IAM policy.
5. STS confirms that the policy of the IAM user making the call to GetFederationToken gives permission to create new tokens.
6. STS returns the temp STS token to the Identity Broker.
7. Identity Broker returns the STS token to the application.
8. Application uses the STS token to make requests to S3.
9. S3 uses IAM to verify STS token and to allow requested operation on the given S3 bucket.
10. IAM provides S3 with go-ahead to perform requested operation.

High-Level Summary:
1. Authenticate (as Identity/User) against 3rd-party (Identity Store: AD/Facebook/Google).
2. Authenticate (as Identity Broker) against STS.
3. Authenticate (as Application) against AWS service to obtain access to resource.

## Web Identity Federation / Amazon Cognito

Web Identity Federation lets you give users access to AWS resources after they have successfully authenticated with a web-based identity provider like Amazon/Facebook/Google. User trades authentication code from Web ID provider for an AWS STS token.

Suggested use case: mobile app which you want to make available to Facebook users. (recommended for social accounts)

Amazon Cognito
* Sign-up / Sign-in to your apps
* Provides guest access
* Acts as identity broker between your app / Web ID provider
* Synchronises user data across multiple devices (mobile, desktop data sync)
* Recommended for mobile apps running on AWS.

Amazon Cognito scenario:
* Mobile shopping app: S3 for product data, DynamoDB for customer data.
* User logs into Facebook, Facebook provides web token.
* Cognito takes web token and exchanges it for STS token.
* Cognito passes STS token to mobile app.
* Mobile app uses STS token to get access to resources for user.

Amazon Cognito benefits:
* No need for mobile app to embed or store AWS credentials locally on the device = increased security.
* Provides users a seamless experience across all devices.

Cognito User Pools: user directories used to manage sign-up and sign-in functionality for mobile/web apps.
* User sign-in directly via. User Pool or indirectly via. identity provider (Amazon/Facebook/Google)
* Cognito acts as identity broker between ID provider and AWS.

## Glacier Vault Lock

Glacier is a low-cost storage service for data archiving and long-term backup.
* _Archives_: a single file or multiple files stored in a .tar or .zip.
* _Vault_: containers which store one or more Archives
* _Vault Lock Policy_: similar to an IAM policy to configure and enforce compliance controls - connfigure write-once-read-many archives / create data retention policies

Example Vault Lock Policy: Enforce archive retention for 1 year (deny archive delete for all archives <365 days old)
```json
"Version":"2012-10-17",
"Statement":[
    {
        "Sid":"deny-based-on-archive-age",
        "Principal":"*",
        "Effect":"Deny",
        "Action":"glacier:DeleteArchive",
        "Resource":[
            "arn:aws:glacier:us-west-2:XXXaccountidXXX:vaults/examplevault"
        ],
        "Condition":{
            "NumericLessThan":{
                "glacier:ArchiveAgeInDays":"365",
            }
        }
    }
]
```

Steps to configuring Vault Locks:
* Create Vault Lock policy.
* Initiate lock by attaching Vault Lock policy to your vault = in-progress state.
* You have 24 hours to validate the lock policy. You can abort within 24 hours.
* Once validated, Vault Lock policies are immutable.

Vault Lock Policy vs. Vault Access Policy:
* https://docs.aws.amazon.com/amazonglacier/latest/dev/vault-lock.html

## AWS Organisations

AWS Organisations is an account management service that lets you consolodate multiple AWS accounts into an organisation so that you can consolidate billing, group your AWS accounts into logical groupings for access control and attach Service Control Policies.

SCPs enable you to restrict, at the account level of granularity, what services and actions the users, groups, and roles in those accounts can do. However, an SCP never grants permissions. The SCP limits permissions for entities in member accounts, including each AWS account root user. SCPs are available only in an AWS organization that has all features enabled, SCPs aren't available if your organization has enabled only the consolidated billing features.

https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scp.html


## Summary / Exam Tips

Resetting Root Users
* Create new root user password / strong password policy.
* Delete 2FA / re-create.
* Delete Access Key ID / Secret Access Key.
* Check existing user accounts, delete if not legit.

IAM policies
* IAM is Global.
* Three different types: (1) Managed Policies (2) Customer Managed Policies (3) Inline Policies

S3 policies
* S3 policies are attached only to S3 buckets (NOT objects). They specify what is ALLOWED/DENIED on the bucket.
* Broken down to the user-level.
* _EXPLICIT DENY ALWAYS OVERRIDES AN ALLOW_.
* S3 ACL's: Legacy access control for enforcing access to S3 OBJECTS.
* S3 policy conflicts: see _policy conflict diagram_ above (IMPORTANT).
* aws:SecureTransport: restrict S3 bucket access to only HTTPS.
* Cross-Region-Replication (CRR):
    * Delete markers are replicated, deleted versions of files are NOT replicated.
    * Versioning must be enabled.
    * Possible to use CRR from one AWS account to another
    * SSL is enabled by default when you configure CRR
    * IAM role must have permissions to replicate objects in destination bucket.
    * Scenario: replicate CloudTrail logs to separate AWS audit account (can only send data there, not read/write).

Pre-signed URLs (CLI/SDK only):
* Access objects using pre-signed URL's
* Exist only for a certain length of time.
* Change TTL by using `expires-in`

STS / Identity Provider
* User provides credentials to Identity Provider (AD/FB/Google) -> AWS STS -> User accesses AWS resource -> AWS resource checks IAM -> access is provided to user.