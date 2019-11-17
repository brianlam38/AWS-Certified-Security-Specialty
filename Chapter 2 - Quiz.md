### Which of the following steps would you need to complete in order to configure Cross Region Replication where source and destination buckets are owned by different accounts?

>The owner of the destination bucket must grant the owner of the source bucket permissions to replicate objects with a bucket policy.
The owner of the source bucket must grant the owner of the destination bucket permissions to replicate objects with a bucket policy.
The owner of the source bucket must grant the owner of the destination bucket permissions to replicate objects with a bucket policy AND the owner of the destination bucket must grant the owner of the source bucket permissions to replicate objects with a bucket policy.
The source and destination bucket must be owned by the same account otherwise Cross Region Replication will not work

```
If you are setting up Cross Region Replication in a cross-account scenario, where source and destination buckets are owned by different AWS accounts, the following additional requirements apply: The owner of the destination bucket must grant the owner of the source bucket permissions to replicate objects with a bucket policy. Further information: https://docs.aws.amazon.com/AmazonS3/latest/dev/crr.html
```

### Which of the following policy types is created and managed completely by AWS?

Customer Managed Policy
>AWS Managed Policy
Inline Policy
All IAM Policies

```
An AWS managed policy is a standalone policy that is created and administered by AWS. Further information: https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html
```

### Which of the following approaches would you use to enable an application running on EC2 to read objects located in an S3 bucket?

>Create an IAM role with read access to the bucket and associate the role with the EC2 instance
Create an IAM user with read access to the bucket and embed the user's credentials in your application code.
Create an IAM policy which allows read access to the bucket and attach the policy directly to the EC2 instance
Create an IAM group with read access to the bucket and add the EC2 instance to the group

```
Embedding user credentials in application code is insecure and not recommended. You can use roles to delegate access to users, applications, or services that don't normally have access to your AWS resources.Further information: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles.htmlhttps://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html
```

### Last week you created a Vault Lock Policy to prevent archived files from being deleted unless they are over 2 years old. But now your CTO has changed their mind and only wants to keep the archives for 1 year. What is your recommended approach?

Modify the Vault Lock and update the retention period to 1 year
Abort the Vault Lock and create a new one to fit the new requirement
Delete the Vault Lock completely and suggest using S3 lifecycle policies instead
> Go back to the CTO and explain that once the Vault Lock is in place, it cannot be changed

```
A vault lock policy is different than a vault access policy. Both policies govern access controls to your vault. However, a vault lock policy can be locked to prevent future changes, providing strong enforcement for your compliance controls. Further information: https://docs.aws.amazon.com/amazonglacier/latest/dev/vault-lock.html
```

### Which of the following does AWS IAM enable you to do? (Choose 4)

> Manage user access to the AWS Console
> Identity Federation with Web Identity providers
> Identity Federation with Active Directory
> Multi-Factor Authentication
Biometric verification

```
AWS Identity and Access Management (IAM) enables you to manage access to AWS services and resources securely. Using IAM, you can create and manage AWS users and groups, and use permissions to allow and deny their access to AWS resources. This includes Identity Federation with SAML 2 compliant Identity Providers like Active Directory and Web Identity providers like Facebook, Google and Amazon.com. Further information: https://aws.amazon.com/iam/https://aws.amazon.com/identity/federation/https://aws.amazon.com/iam/details/mfa/
```

### The AWS STS API supports which of the following methods of access? (Choose 3)

Kubernetes Federation
>Web Identity Federation
>Active Directory Federation
Azure AD Federation
>Cross Account Access

```
STS enables Web ID Federation, AD Federation and Cross Account Access. Further information: https://docs.aws.amazon.com/STS/latest/APIReference/Welcome.htmlhttps://aws.amazon.com/identity/federation/
```



