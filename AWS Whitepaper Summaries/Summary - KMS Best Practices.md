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

Key Policy Example - create and use an encrypted Amazon Elastic Block Store (EBS) volume.
```json
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
// Allow IAM principal to create, list, revoke GRANTS (used to delegate subset of permissions to AWS services/principals to use your keys) for EC2 service.
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
* Ensure __Separation of Duty__ by NOT using __kms:*__ in an IAM or Key Policy: this grants both ADMINISTRATIVE and USAGE permissions on all CMKs to which the principal has access to.
* Ensure __"Effect":"Deny"__ is NOT used with __"NotPrincipal"__: permissions are explicitly denied to all principals EXCEPT for the principals specified under `NotPrincipal`.

Cross Account Sharing of Keys

CMK Grants

Encryption Context

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
