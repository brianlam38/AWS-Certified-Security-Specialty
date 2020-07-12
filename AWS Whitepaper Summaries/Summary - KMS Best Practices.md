# AWS Key Management Service Best Practices

## Identity and Access Management

AWS KMS and IAM policies - use IAM Policies in combination with Key Policies to control access to CMKs
* __identity-based policy__: policy attached to IAM entities (users, groups, roles).
* __resource-based policy__: policy attached to resources OUTSIDE of IAM.
* IAM policies are not enough by themselves to allow access to a CMK, but can be used _IN COMBINATION with a Key Policy_ to grant access. To do this, ensure that the CMK Key Policy includes a _POLICY STATEMENT that enables IAM policies_.

Key Policy - a resource-based policy attached to CMKs which control access to the CMK
* All CMKs have a Key Policy.
* To access an encrypted resource: (1) Principal needs permissions to use the resource (2) Principal needs permission to use the encryption key that protects the resource
* `kms:viaService`: constrain CMK access so that it can only be used specified AWS services.

Key Policy Example - create and delegate use of an encrypted Amazon Elastic Block Store (EBS) volume to an EC2.
* __CMK Grants__ are used to delegate subset of permissions to AWS services/principals to use your keys.
```javascript
// Allow IAM principal to generate a data key (encrypted by CMK) + decrypt data key (using same CMK)
// Data key: used to encrypt data.
{
    "Sid": "Allow for use of this Key", // sid = a description for policy statements
    "Effect": "Allow",
    "Principal": {
        "AWS": "arn:aws:iam::111122223333:role/UserRole"
    },
    "Action": [
        "kms:GenerateDataKeyWithoutPlaintext",  // returns a unique symmetric data key (encrypted by CMK)
        "kms:Decrypt"
    ],
    "Resource": "*"
},
// Allow IAM principal to create, list, revoke CMK Grants for EC2 service.
// EC2 will use delegated permissions to access an encrypted EBS volume, to re-attach it back to an instance if the volume gets detached due to a planned or unplanned outage.
{
    "Sid": "Allow for EC2 Use",
    "Effect": "Allow",
    "Principal": {
        "AWS": "arn:aws:iam::111122223333:role/UserRole"
    },
    "Action": [
        "kms:CreateGrant", // adds grant to CMK, allowing a GRANTEE principal to use the CMK when conditions of grant are met.
        "kms:ListGrants",
        "kms:RevokeGrant"
    ],
    "Resource": "*",
    "Condition": {
        "StringEquals": {
            "kms:ViaService": "ec2.us-west-2.amazonaws.com" // only EC2 can use the createed grants
        }
    }
}
```

Key Policies - Least Privilege / Separation of Duties
* __Ensure Separation of Duty by NOT using "kms:*"__: in an IAM or Key Policy: this grants both ADMINISTRATIVE and USAGE permissions on all CMKs to which the principal has access to. Users with `kms:PutKeyPolicy` permission for a CMK can completely replace the Key Policy.
* __Ensure "Effect":"Deny" is NOT used with "NotPrincipal"__: permissions are explicitly denied to all principals EXCEPT for the principals specified under `NotPrincipal`.

Cross Account Sharing of Keys (2 steps)
1. __Key Policy__ for the CMK must give the __root principal of external account__ (or users/roles in the external account) permission to use the CMK.
2. __IAM Policy__ must be attached to IAM users/roles in the external account to delegate permissions specified in the Key Policy. This is reliant on the trusted account to ensure that delegated permissions are LEAST PRIVILEGE..

Encryption Context - an additional layer of authentication for KMS API calls
* A optional key-value pair of data that can contain contextual information that you want associated with KMS-protected information. IF encryption context value is used in ENCRYPTION <-> must be used also in DECRYPTION.
* __Additional Authentication Data (AAD)__: encryption context key-value pair is incorporated into AAD in KMS-encrypted ciphertext.
* __Not a secret__: encryption context appears in plaintext in CloudTrail Logs so you can use it to identify/categorise cryptographic operations. Do NOT store sensitive info in the key-value pair.
* __Limiting access/scope__: encryption context can be used to limit access to your resources e.g. only S3 buckets with context `bucket-name:helloworld` can be encrypted/decrypted under the CMK.

Multi-Factor Authentication - can be added via. conditional statement in CMK Key Policy to protect critical KMS calls
* Example: Key Policy with critical KMS calls: `PutKeyPolicy`, `ScheduleKeyDeletion`, `DeleteAlias` and `DeleteImportedKeyMaterial`
```javascript
{
    "Sid": "MFACriticalKMSEvents",
    "Effect": "Allow",
    "Principal": {
        "AWS": "arn:aws:iam::111122223333/user/ExampleUser"
    },
    "Actions": [
        "kms:DeleteAlias",
        "kms:DeleteImportedKeyMaterial",
        "kms:PutKeyPolicy",
        "kms:ScheduleKeyDeletion"
    ],
    "Resource": "*",
    "Condition": {
        "NumericLessThan": {
            "aws: MultiFactorAuthAge": "300"
        }
    }
}
```

## Detective Controls

_Detective Controls ensures that you properly configure AWS KMS to log the necessary information you need to gain greater visibility into your environment._

CMK Auditing - KMS is integrated natively with CloudTrail
* All KMS calls are automatically logged in files delivered to an S3 bucket that you specify.
* Monitor for specific KMS calls such as `ScheduleKeyDeletion`, `PutKeyPolicy`, `DeleteAlias`, `DisableKey`, `DeleteImportedKeyMaterial` on your KMS keys.
* KMS also produces CloudWatch Events when your CMK is rotated, deleted, and imported key material expires.

CMK Use Validation - validate that your CMKs are being used properly / aigns with best practices
* __AWS Config__: E.g. Config rule `ENCRYPTED_VOLUMES` can be used to validate that attached EBS volumes are encrypted.
* __Key Tags__: A CMK can a tag applied to it, to correlate back to a business category e.g. cost center, application name, owner etc. Use CloudTrail to verify that the CMK being used belongs to the same cost center of the resource that the CMK is used on (e.g. Marketing CMK used on Marketing S3 Storage).

## Infrastructure Security

_Infrastructure Security provides you with the best practices on how to configure AWS KMS to ensure that you have an agile implementation that can scale with your business, while protecting your sensitive information._

Customer Master Keys (CMKs) are used to:
1. Encrypt DATA BLOCKS of up to __4KB__. OR;
2. Encrypt DATA KEYS, which protect underlying data of ANY SIZE.

CMKs - AWS-managed CMK vs Customer-managed CMKs
* __Creation__: AWS generated || Customer generated
* __Rotation__: Once/3years automatically || Once/year opt-in manually
* __Deletion__: Can't be deleted || Can't be deleted
* __Scope of Use__: Limited to specific AWS service || Controlled via. KMS Key Policy /IAM Policy
* __Key Access Policy__: AWS managed || Customer managed
* __User Access Mgmt__: IAM policy || IAM policy

Customer-managed CMKs - 2 options for creating underlying key material
1. KMS generates cryptographic key material for you.
2. Customer imports their own cryptographic key material. Benefits include:
    * Allows you to meet compliance requirements.
    * Ability to set an expiration time for key material in AWS and manually delete it, but also make it available again in the future.
    * Additional durability and disaster recovery as you can keep the key material outside of AWS.

CMK Key Aliases - abstract CMK users away from underlying Region-specific key ID and key ARN
* __Multi-region apps__: can benefit from using the same key alias to refer to CMKs in multiple-regions without worrying about key ID or key ARN.
* __Recommended alias format__: `alias/<Environment>-<Function>-<Team>` e.g. `alias/development-mfakey-integrations`
* CMK aliases can't be used within policies (Key Policies, IAM Policies, KMS Grants) as mapping of alias to keys can be manipulated outside the policy, which would allow privilege escalation.

Using AWS KMS at Scale - Envelope Encryption
* __Envelope Encryption__ can be used to encrypt a unique Data Key, which is used to encrypt plaintext data.
* __Reduce no. of requests to AWS KMS__: decrypt the encrypted Data Key with the CMK once, then cache the plaintext Data Key for repeated use for X period of time.
* __Enable Disaster Recovery__ by copying your encrypted data between Regions and only re-encrypting Data Keys with Region-specific CMKs.


## Data Protection

_Data Protection addresses some of the common use cases for using KMS to protect sensitive info_

USE CASE: Encrypting PCI Data Using AWS KMS
* KMS service meets requirements of PCI DSS Level 1 certification.
* __Reduce burden of managing encryption libraries__: encrypt Primary Account Number (PAN) data with a CMK.
* __KMS requests are logged in CloudTrail__: CMK use can be audited easily.

USE CASE: Secret Management Using AWS KMS and Amazon S3
* 

Encrypting Lambda Environment Variables

Encryption Data within Systems Manager Paramter Store

Enforcing Data at Rest Encryption within AWS Services

Data at Rest Encryption with Amazon S3

Data at Rest Encryption with Amazon EBS

Data at Rest Encryption with Amazon RDS

## Incident Response

Security Automation of AWS KMS

Deleting and Disabling CMKs
