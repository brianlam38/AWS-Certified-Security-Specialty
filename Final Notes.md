# Final Note Summary

## Chapter 2 - IAM, S3 and Security

S3 Bucket Policy / ACL / IAM conflicts:
* __Explicit Deny Overrides__: An EXPLICIT DENY will always override any ALLOW.
* __Policy Conflicts__: Whenever an AWS principal (user, group or role) issues a request to S3, the authorization decision depends on the union of all the IAM policies, S3 bucket policies and S3 ACLs that apply.
* __Policy Conflict flow__:
    1. Decision starts at DENY by default.
    2. Any applicable policies? ( YES = CONTINUE | NO = DENY )
    3. Does a policy have an EXPLICIT DENY? ( YES = DENY | NO = CONTINUE )
    4. Does a policy have an ALLOW? ( YES = ALLOW | NO = DENY)

S3 Cross-Region Replication (CRR)
* __AUDIT account__: best CRR example
    1. CloudTrail logs AWS accounts XYZ.
    2. Turn on CRR to replicate logs to AUDIT account.
    3. AWS accounts XYZ can only replicate logs, but not read/write logs in AUDIT account.
* CRR replicates: new objects (_encrypted w/ SSE-S3 or SSE-KMS + unencrypted_), metadata, ACL updates, tags
* CRR NOT replicate: objects before CRR, objects encrypted by SSE-C, objects which bucket owner does NOT have permissions, object deletes of a specific version.

Secure S3 bucket access via. CloudFront Origin Access Identity
1. Goto CloudFront -> __Origins and Origin Groups__
2. Turn on __Restrict Bucket Access__ -> Create an __Origin Access Identity__
3. Turn on __Grant Read Permissions on Bucket__ to allow CloudFront OAI to perform `s3:GetObject`
Resulting Policy:
```javascript
{
	"Sid": "1",
	"Effect": "Allow",
	"Principal": {
		"AWS": "arn:aws:iam::cloudfront:user/CloudFront Origin Access Identity EAF5XXXXXXXXX"
		},
	"Action": "s3:GetObject",
	"Resource": "arn:aws:s3:::AWSDOC-EXAMPLE-BUCKET/*"
}


## Chapter 3 - Logging and Monitoring