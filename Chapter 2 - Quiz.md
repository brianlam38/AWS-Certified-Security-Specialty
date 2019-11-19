### Which of the following steps would you need to complete in order to configure Cross Region Replication where source and destination buckets are owned by different accounts?



__The owner of the destination bucket must grant the owner of the source bucket permissions to replicate objects with a bucket policy.__

The owner of the source bucket must grant the owner of the destination bucket permissions to replicate objects with a bucket policy.

The owner of the source bucket must grant the owner of the destination bucket permissions to replicate objects with a bucket policy AND the owner of the destination bucket must grant the owner of the source bucket permissions to replicate objects with a bucket policy.

The source and destination bucket must be owned by the same account otherwise Cross Region Replication will not work



```

If you are setting up Cross Region Replication in a cross-account scenario, where source and destination buckets are owned by different AWS accounts, the following additional requirements apply: The owner of the destination bucket must grant the owner of the source bucket permissions to replicate objects with a bucket policy. Further information: https://docs.aws.amazon.com/AmazonS3/latest/dev/crr.html

```



### Which of the following policy types is created and managed completely by AWS?



Customer Managed Policy

__AWS Managed Policy

Inline Policy

All IAM Policies



```

An AWS managed policy is a standalone policy that is created and administered by AWS. Further information: https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html

```



### Which of the following approaches would you use to enable an application running on EC2 to read objects located in an S3 bucket?



__Create an IAM role with read access to the bucket and associate the role with the EC2 instance__

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

__Go back to the CTO and explain that once the Vault Lock is in place, it cannot be changed__



```

A vault lock policy is different than a vault access policy. Both policies govern access controls to your vault. However, a vault lock policy can be locked to prevent future changes, providing strong enforcement for your compliance controls. Further information: https://docs.aws.amazon.com/amazonglacier/latest/dev/vault-lock.html

```



### Which of the following does AWS IAM enable you to do? (Choose 4)



__Manage user access to the AWS Console__

__Identity Federation with Web Identity providers__

__Identity Federation with Active Directory__

__Multi-Factor Authentication__

Biometric verification



```

AWS Identity and Access Management (IAM) enables you to manage access to AWS services and resources securely. Using IAM, you can create and manage AWS users and groups, and use permissions to allow and deny their access to AWS resources. This includes Identity Federation with SAML 2 compliant Identity Providers like Active Directory and Web Identity providers like Facebook, Google and Amazon.com. Further information: https://aws.amazon.com/iam/https://aws.amazon.com/identity/federation/https://aws.amazon.com/iam/details/mfa/

```



### The AWS STS API supports which of the following methods of access? (Choose 3)



Kubernetes Federation

__Web Identity Federation__

__Active Directory Federation__

Azure AD Federation

__Cross Account Access__



```

STS enables Web ID Federation, AD Federation and Cross Account Access. Further information: https://docs.aws.amazon.com/STS/latest/APIReference/Welcome.htmlhttps://aws.amazon.com/identity/federation/

```



### What is a permissions boundary used for?



It is used to prevent resources based in one region form accessing resources based in another

__It is used to limit the maximum permissions for a user, group or role__

It is used to prevent on AWS account from accessing resources belonging to another account

It is used to limit the privileges of the Root user



```

A permissions boundary is an advanced feature in which you use a managed policy to set the maximum permissions that an identity-based policy can grant to an IAM entity. When you set a permissions boundary for an entity, the entity can perform only the actions that are allowed by both its identity-based policies and its permissions boundaries.

```



### The root administrator has left your company, what should you do to ensure your AWS account is secure? (Choose 4)



Delete all IAM accounts and recreate them with new credentials

__Delete any root owned access keys if they exist__

Delete the root account and recreate it with new credentials

Create new access keys for root

__Change the root password__

__Review your IAM accounts and delete any account which belongs to the user who has left the company__

__Deactivate and reactivate Multi Factor Authentication__



```

The following best practices are recommended in order to secure the root account: configure MFA, use a strong password and rotate it regularly and delete the root access key and secret access key. It is also best practise to delete any account associated with a user who has left the company. Further information: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html

```



### Which of the following can you achieve using Amazon Cognito? (Choose 2)



Self-service password resets for Facebook users

__Federated access to your web application for Facebook users__

Federated access to your web application for Active directory users outside your organisation

__Anonymous guest access to your web application__



```

Amazon Cognito provides authentication, authorization, and user management for your web and mobile apps. Your users can sign in directly with a user name and password, or through a third party such as Facebook, Amazon, or Google. Further information:

```



### To which of the following entities can you attach an IAM Policy? (Choose 2)



__IAM Roles__

EC2 Instances

__IAM Groups__

S3 Buckets



```

You manage access in AWS by creating policies and attaching them to IAM identities (users, groups of users, or roles) or AWS resources. A policy is an object in AWS that, when associated with an identity or resource, defines their permissions. You can attach an IAM Policy to a user, group or role. You can associate a role with an EC2 instance but you cannot attach an IAM Policy directly to the EC2 instance. You cannot attach policies to S3 buckets. Further information: https://docs.aws.amazon.com/IAM/latest/UserGuide/introduction_access-management.html

```



### Which of the following types of IAM Policy is created and administered by you and can be attached to multiple users, groups or roles within your account?



__Customer Managed Policies__

All IAM Policies

Inline Policies

AWS Managed Policies



```

Customer Managed Policies are created and administered by you and can be attached to multiple users, groups or roles within your account Further information: https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html

```



### Which feature of AWS would you use to configure consolidate billing, group your AWS accounts into logical groupings for access control and attach Service Control Policies?



Web Identity Federation

AWS IAM

Cross Account Access

__AWS Organizations__



```

Using AWS Organizations, you can create Service Control Policies (SCPs) that centrally control AWS service use across multiple AWS accounts, consolidate billing for multiple accounts and create groups of accounts and apply and manage policies for those groups.. Further information: https://aws.amazon.com/organizations/

```



### How would you go about enforcing a mandatory 5 year retention policy on your Glacier archives?



Use an S3 Bucket policy which prevents users from deleting archives which are less than 5 years in age

Use a lifecycle policy which moves all archives less than 5 years in age to WORM storage

Use a Vault Access Policy which prevents users from deleting archives which are less than 5 years in age

__Use a Vault Lock Policy which prevents any user from deleting archives which are less than 5 years in age__



```

A vault lock policy is different than a vault access policy. Both policies govern access controls to your vault. However, a vault lock policy can be locked to prevent future changes, providing strong enforcement for your compliance controls. You can use the vault lock policy to deploy regulatory and compliance controls, which typically require tight controls on data access. In contrast, you use a vault access policy to implement access controls that are not compliance related, temporary, and subject to frequent modification. Vault lock and vault access policies can be used together. 



https://docs.aws.amazon.com/amazonglacier/latest/dev/vault-lock.html

```



### Which of the following best describes a Glacier Vault?



__A container which stores one or more Glacier archives__

A container which stores multiple S3 buckets

A secure place to store security tokens, passwords, certificates, API keys, and other secrets

A single file or multiple files stored in a .tar or .zip format within Glacier



```

In Amazon S3 Glacier (Glacier), a vault is a container for storing archives, and an archive is any object, such as a photo, video, or document that you store in a vault. An archive is the base unit of storage in Glacier. You can store an unlimited number of archives in a vault. Further information: https://docs.aws.amazon.com/amazonglacier/latest/dev/working-with-vaults.html

```



### You have created a website hosted in S3 and configured a CloudFront web distribution. Which steps do you need to take to force your users to access your site using CloudFront and not directly using the S3 url? (Choose 3)



__Select "Restrict Bucket Access" in the Origin Settings of your CloudFront Distribution__

Change the permissions on your Amazon S3 bucket so that only the CloudFront endpoint has access

__Configure the bucket policy on your Amazon S3 bucket so that only the origin access identity has read permission for objects in the bucket__

__Create an origin access identity for your S3 origin__



```

Create an origin access identity, which is a special CloudFront user, associate the origin access identity with your distribution. Change the permissions either on your Amazon S3 bucket or on the files in your bucket so that only the origin access identity has read permission (or read and download permission). When your users access your Amazon S3 files through CloudFront, the CloudFront origin access identity gets the files on behalf of your users. If your users request files directly by using Amazon S3 URLs, they're denied access. Further information: https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-restricting-access-to-s3.html

```



### Which of the following is correct in relation to Service Control Policies? (Choose 2)



__An SCP applies to all Organizational Units and accounts below the Organizational Unit to which it has been attached__

They can be used to allow or deny access to AWS resources

__They can only be used to limit permissions to AWS resources__

They are deny by default and can only be used to allow access to AWS resources



```

SCPs enable you to restrict, at the account level of granularity, what services and actions the users, groups, and roles in those accounts can do. However, an SCP never grants permissions. The SCP limits permissions for entities in member accounts, including each AWS account root user. SCPs are available only in an AWS organization that has all features enabled, SCPs aren't available if your organization has enabled only the consolidated billing features. Further information: https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scp.html

```



### Which of the following IAM Policies can you change to update them when the needs of your organization change? (Choose 2)



__Inline Policies__

__Customer Managed Policies__

AWS Managed Policies

All IAM Policies



```

AWS Managed Policies cannot be changed, only Customer Managed and Inline Policies can be changed and updated to reflect the needs of your organization. Further information: https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html

```



### Which AWS API gets called used when a user accesses AWS using their Active Directory credentials?



REST

SAML 2.0

__Security Token Service__

Cognito



```

The AWS Security Token Service (STS) is a web service that enables you to request temporary, limited-privilege credentials for AWS Identity and Access Management (IAM) users or for users that you authenticate (federated users). Further information: https://docs.aws.amazon.com/STS/latest/APIReference/Welcome.html

```



### What is meant by the "principal" in relation to AWS and permissions?



The principal specifies the AWS root account ID

The principal specifies the name of the resource to which you are either allowing or denying access to

__The principal specifies the user, account, service, or other entity that is allowed or denied access to a resource__

The principal is used to define which region the permissions you are specifying will apply to



```

The Principal element specifies the user, account, service, or other entity that is allowed or denied access to a resource. Further information: https://docs.aws.amazon.com/AmazonS3/latest/dev/s3-bucket-user-policy-specifying-principal-intro.htmlhttps://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html

```



### You have created a new user and added them to a group which allows the following IAM permissions: s3:Get* and s3:List* for all S3 resources. Which of the following statements is correct? (Choose 2)



The user is able to add objects to any S3 bucket

The user is able to delete objects from any S3 bucket

__The user is able to read objects in any S3 bucket__

__The user is able to list the objects in any S3 bucket__



```

The user is only able to read and list objects in any S3 bucket. all other actions are denied by default. If you want to enable write access then you will need to add further permissions. Further information: https://aws.amazon.com/blogs/security/writing-iam-policies-how-to-grant-access-to-an-amazon-s3-bucket/

```



### Which of the following would you use to define the IAM permissions which specify what can be done and what actions can be taken against resources in your AWS environment?



IAM Role

__IAM Policy__

IAM User

IAM Group



```

You manage access in AWS by creating policies and attaching them to IAM identities (users, groups of users, or roles) or AWS resources. A policy is an object in AWS that, when associated with an identity or resource, defines their permissions. Further information: https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html

```



### You would like to give a user temporary access to a single object in your S3 bucket, which of the following is the most secure way to do this?



__Create a presigned url and share it with the user__

Configure read only access to the object using a bucket Access Control List, then remove the access after a set number of hours has elapsed

Give the user read access to the bucket

Change the ownership of the object to the user who needs to access it



```

All objects by default are private. Only the object owner has permission to access these objects. However, the object owner can optionally share objects with others by creating a presigned URL, using their own security credentials, to grant time-limited permission to download the objects. Further information: https://docs.aws.amazon.com/AmazonS3/latest/dev/ShareObjectPreSignedURL.html

```



### You have created a new s3 bucket and you want to force users to use HTTPS when uploading objects to your bucket, which approach should you use?



Configure an IAM policy which includes a condition statement which denies requests which do not use aws:SecureTransport

__Configure a bucket policy which includes a condition statement which denies requests which do not use aws:SecureTransport__

Configure key policy which includes a condition statement which denies requests which do not use aws:SecureTransport

Configure an ACL which includes a condition statement which denies requests which do not use aws:SecureTransport



```

Use a bucket policy which includes a condition statement denying access to anyone not using HTTPS (aws:SecureTransport) Further information: https://aws.amazon.com/blogs/security/how-to-use-bucket-policies-and-apply-defense-in-depth-to-help-secure-your-amazon-s3-data/

```



### You have created an S3 bucket policy which denies access to all users. Later on you add an additional statement to the bucket policy to allow read only access to one of your colleagues, however even after updating the policy, your colleague is still getting an access denied message. What is the reason for this?



The IAM policy doesn't allow the user to access the bucket

It takes a few minutes for a bucket policy to take effect

An explicit deny always overrides an allow, so access will be denied

You need to update the ACL in the bucket



```

An explicit deny always overrides an allow, so access will be denied. - Even if the bucket policy also includes a statement allowing access for the user and the user also has an IAM policy which allows access. A deny always trumps an allow! Further information: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html

```



### Which of the following policies work in combination to define who or what can an access an S3 bucket? (Choose 2)



S3 Access Control Policies

S3 Object Policy

__S3 Bucket Policy__

__IAM Policy__



```

An IAM Policy is an entity that, when attached to an identity or resource, defines their permissions. A Bucket Policy is a resource-based AWS Identity and Access Management (IAM) policy. You add a bucket policy to a bucket to grant other AWS accounts or IAM users access permissions for the bucket and the objects in it. IAM Policies and Bucket Policies work together in combination to determine who or what can access an S3 bucket and what actions they are allowed to take. Further information: https://docs.aws.amazon.com/AmazonS3/latest/dev/using-iam-policies.html

```



### Which kind of AWS IAM Policy would you use if you strictly want to attach the policy to a single user and be certain that it cannot be accidentally attached to any other user?



AWS Managed Policy

Customer Managed Policy

__Inline Policy__

Any IAM Policy type can be configured to enforce this



```

Only an Inline Policy enforces a strict one-to-one relationship between the policy and the entity to which it is attached. Further information: https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html#inline-policies

```



### You would like to restrict access to S3 across a number of different AWS accounts in your organization. Which AWS feature can you use to do this?



__Service Control Policy__

Consolidated Billing

S3 bucket policies

IAM Policies



```

SCPs enable you to restrict, at the account level of granularity, what services and actions the users, groups, and roles in those accounts can do. Further information: https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scp.html

```



### You have configured Cross Region Replication on your S3 bucket and would like to enforce the use of SSL. How would you approach this?



__Do nothing, SSL is enabled by default when you configure Cross Region Replication__

Select SecureTransport in the console when configuring cross Region Replication

Configure a bucket policy which includes a condition statement which denies requests which do not use aws:SecureTransport

Select Use SSL in the console when configuring cross Region Replication



```

Amazon S3 encrypts all data in transit across AWS Regions using Secure Sockets Layer (SSL). Further information: https://docs.aws.amazon.com/AmazonS3/latest/dev/crr-how-setup.html

```



### You have created a new S3 bucket and you would like to configure read and write access to this bucket, only for users who are members of the Development, Test and QA teams. Each team has a different IAM Group defined in AWS. Which of the following is the simplest way to configure this?



Configure public access on the S3 bucket

Create an IAM policy allowing read / write access to only this bucket and attach it to each user in the Development, Test and QA teams

Attach an IAM policy which gives S3FullAccess to the Development, Test and QA IAM groups

__Use a bucket policy to allow read and write access to the Development, Test and QA IAM groups__



```

Allowing public access allows access for everyone, S3FullAccess will give the groups full access to all S3 buckets, attaching an IAM policy to each user in turn adds complexity as well as administrative overhead. The simplest way to do this is to use a bucket policy. Further information: https://docs.aws.amazon.com/AmazonS3/latest/dev/example-bucket-policies.html

```



### Which four things are returned by GetFederationToken when a user successfully logs to AWS in using their Active Directory credentials?



__Access key, secret access key, session token, expiration__

User name, temporary password, SAML token, expiration

Access key, secret access key, token, presigned url

A presigned url, secret access key, session token, expiration



```

A successful call to GetFederationToken returns: AccessKeyId, SecretAccessKey, SessionToken and Expiration Further information: https://docs.aws.amazon.com/cli/latest/reference/sts/get-federation-token.html

```



### Which of the following mechanisms would you use to apply fine grained permissions on an object in S3?



__S3 ACL__

Key Policy

Bucket Policy

IAM Policy



```

Only ACLs allow you define object level permissions in S3. Further information: https://docs.aws.amazon.com/AmazonS3/latest/dev/acl-overview.html



```



### Which of the following statements is correct in relation to user federation with Active Directory? (Choose 2)



__The user must browse to the ADFS sign-in page__

The user must browse to the AWS sign-in page

__Users do not need to have IAM credentials__

All Active Directory users require corresponding IAM credentials within your AWS account



```

https://aws.amazon.com/blogs/security/enabling-federation-to-aws-using-windows-active-directory-adfs-and-saml-2-0/

```



### Which of the following statements is correct in relation to S3 cross-region replication?



__SSL is enabled by default__

SSL is disabled by default

The source and destination bucket may be in the same region

You are charged extra for SSL



```

S3 encrypts all data in transit across AWS Regions using Secure Sockets Layer (SSL). Further information: https://docs.aws.amazon.com/AmazonS3/latest/dev/crr-how-setup.html

```



### You are configuring a CloudFront web distribution for your website hosted in S3. Your marketing team has already purchased a registered domain name that they would like to use for the new website. Which kind of SSL certificate would you use in this configuration?



__Use a custom SSL certificate with the certificate stored in ACM in us-east-1__

Use the default CloudFront certificate with the certificate stored in ACM in us-east-1

Use the default CloudFront certificate with the certificate stored in IAM

Use a custom SSL certificate with the certificate stored in ACM in us-east-2



```

You must use a custom certificate if you want to use your own domain name. The certificate may be stored in IAM or in ACM. To use an ACM Certificate with Amazon CloudFront, you must request or import the certificate in the US East (N. Virginia) region. ACM Certificates in this region that are associated with a CloudFront distribution are distributed to all the geographic locations configured for that distribution. Further information: https://docs.aws.amazon.com/acm/latest/userguide/acm-regions.html

```

