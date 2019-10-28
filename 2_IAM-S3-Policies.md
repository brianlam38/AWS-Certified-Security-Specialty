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

__Whenever an AWS principal (user, group or role) issues a request to S3, the authorization decision depends on the union of all the IAM policies, S3 bucket policies and S3 ACLs that apply.

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

