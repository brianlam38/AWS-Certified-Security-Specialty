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
* A optional key-value pair of data that can contain contextual information that you want associated with KMS-protected information. 
* The key-value pair is incorporated into __Additional Authentication Data (AAD)__ in KMS-encrypted ciphertext.
* If you use the encryption context value in ENCRYPTION, you must also use it in DECRYPTION of ciphertext.
* The encryption context is NOT a secret - it appears in plaintext in CloudTrail Logs so you can use it to identity/categorise your cryptographic operations.
* You can use encryption context inside Key Policies to enforce tighter controls for your encrypted resources.

Multi-Factor Authentication

## Detective Controls

CMK Auditing

CMK Use Validation
* Key Tags

## Infrastructure Security

Customer Master Keys: AWS-managed and Customer-managed CMKs

Customer Master Keys: Key Creation and Management

Customer Master Keys: Key Aliases

Using AWS KMS at Scale

## Data Protection

Common AWS KMS Use Cases

* Encrypting PCI Data Using AWS KMS
* Secret Management Using AWS KMS and Amazon S3
* Encrypting Lambda Environment Variables
* Encryption Data within Systems Manager Paramter Store
* Enforcing Data at Rest Encryption within AWS Services
* Data at Rest Encryption with Amazon S3
* Data at Rest Encryption with Amazon EBS
* Data at Rest Encryption with Amazon RDS

## Incident Response

Security Automation of AWS KMS

Deleting and Disabling CMKs
