# AWS Certified Security Special - Cheatsheet

S3 Security:
* __Access control__: S3 Bucket Policy, IAM Policy.
* __CloudFront-only access__: CloudFront Origin Access Identity (OAI).
* __Private (within-VPC) access__: VPC Endpoints using `aws:SourceVpce` in S3 Bucket Policy.
* __Encryption__: Client-side via. AWS SDKs, server-side via. SSE-S3, SSE-KMS, SSE-C.
* __Cross-Region Replication__:
    * Only applies to NEW objects. Cannot replicate SSE-C encrypted objects, objects not belonging to bucket owner, object deletes of a specific version.
    * Object replica CMK-encryption (must be in same region) by referencing `ReplicaKmsKeyId`.
    * Permissions #1: (src acct) IAM role with Trust Policy for S3-service principal to assume role.
    * Permissiosn #2: (src acct) IAM role with Permission Policy to `s3:GetReplicationConfiguration` and to perform Replication actions to dest bucket.
* __Presigned-URL access__: temporary S3 object access using your own credentials.

STS Security:
* __STS Authentication Steps__:
    1. Identity/User authenticate against the Identity Store/Provider (Okta, AD, FB, Google) using user/pass.
    2. Identity Broker authenticates against STS using `sts:GetFederationToken` to obtain temp STS token.
    3. Application authenticates against AWS service with temp STS token to access requested resource.

Cognito (for web and mobile app authZ/authN)
* __User Pools__: for authentication. User sign-in through User Pool OR federate through 3rd-party IdP.
* __User Identity Pools__: for authorization. Authorize your users (sourced from User Pools, FB, Google) to different AWS services.
* __Access to API Gateway via. User Pools__: Use a User Pool to control access to APIs in API Gateway via. an identity token obtained, then passed to `Authorization` header.

Glacier
