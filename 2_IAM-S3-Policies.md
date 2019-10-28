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



