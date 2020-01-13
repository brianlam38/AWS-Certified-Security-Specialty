# Infrastructure Security

## AWS Key Management Service (KMS)

KMS is a managed service that makes it easy for you to create and control the encryption keys used to encrypt your data + uses Hardware Security Modules (HSMs) to protect the security of your keys.

*KMS is region-specific.*

Customer-Master-Keys (CMK)
* Is a logical representation of a master key, typically used to generate/encrypt/decrypt *Data Keys* used to encrypt your actual data - this practice is known as *Envelope Encryption*.
* CMKs consist of:
    * Alias
    * Creation date
    * Description
    * Key state
    * Key material (either customer provided or AWS provided)
* CMKs can NEVER be exported.
* You cannot delete CMKs immediately, only disable them with a 7-30 day waiting period before deletion.
* There are three types of CMKs:
    1. Customer managed CMKs - customer owned / imported keys in your account (full control)
    2. AWS managed CMKs - AWS managed keys in your account that are associated with an AWS service
    3. AWS owned CMKs - AWS owned keys that are NOT in your account for securing data in multiple AWS accounts (no control)

Customer-managed CMK: Importing your own Key Material into KMS
1. Create a customer-managed CMK with no key material by selecting "External" for the key material origin (not useable yet).
2. Import key material - select Wrapping Algorithm SHA1.
3. Import key material - download Wrapping Key (public key) as `PublicKey.bin` and Import Token `ImportTokenxxx`.
4. Use `openssl` and follow instructions here to generate key material and encrypt it with the Wrapping Key: https://docs.aws.amazon.com/kms/latest/developerguide/importing-keys-encrypt-key-material.html.
    * Generate a 256-bit symmetric key and save it in a file named `PlaintextKeyMaterial.bin`: 
    `$ openssl rand -out PlaintextKeyMaterial.bin 32`
    * Encrypt the key material with the public Wrapping Key you downloaded earlier
    ```
    $ openssl rsautl -encrypt \
                 -in PlaintextKeyMaterial.bin \
                 -oaep \
                 -inkey PublicKey.bin \
                 -keyform DER \
                 -pubin \
                 -out EncryptedKeyMaterial.bin
    ```
5. Upload `EncryptedKeyMaterial.bin` and `ImportTokenxxx`.
6. The key is now available for use.

Why import your own Key Material:
* Compliance - prove that randomness meets youre requirements.
* Extend your existing processes to AWS.
* Deletion of key-material without a 7-30 days wait.
* To be resilient to AWS failure by storing keys outside AWS.

Considerations of importing your own Key Material:
* You CANNOT use the same `EncryptedKeyMaterial` and `ImportToken` files twice - it is SINGLE USE only.
* You CANNOT *enable automatic key rotation* for a CMK with imported key material.
* You CAN *manually rotate* a CMK with imported key material.
^Do this by creating a new CMK then import the new key material into that CMK (i.e. repeat the same process as creating a new key)
* You can delete imported keys immediately by deleting the Key Material.

Scenario #1: User disables a KMS key - event-driven security.
* User makes API call -> CloudTrail logs call -> CloudTrail sends Event Source to CloudWatch
* CloudWatch Event Rules is invoked -> Event Target for rule is a Lambda -> Lambda detects that user has disabled a key in KMS
* Lambda responds by auto re-enables key in KMS and/or fire off an SNS notification to security team.

Scenario #2: User disables a KMS key - AWS Config monitoring KMS events.
* AWS Config monitors and stores the KMS event into the Config S3 Bucket.
* Standard or Custom Rule (Lambda) is triggered which detects the KMS-disable.
* Rule will notify AWS Config -> AWS Config fires off SNS notification to security team.

Read the AWS KMS FAQ: https://aws.amazon.com/kms/faqs/

## KMS Key Rotation Options

Extensive re-use of encryption keys is not recommended.
Best practice is to rotate keys on a regular basis.
Frequency of key rotation is dependant on local laws, regulations and corporate policies.
Method of rotation depends on the type of key you are using.
1. AWS Managed Key
2. Customer Managed Key
3. Customer Managed w/ imported key material.

Key Rotation: AWS Managed Keys
* Automatic rotatation every 3 years.
* No automatic rotation
* AWS manages everything and saves old backing key (key material)

Key Rotation: Customer Managed Keys
* Automatic rotation every 1 year (disabled by default)
* Manual rotation is possible
* Create a new CMK -> update apps / key-alias to use the new CMK (be careful of old-key deletion)

Key Rotation: Customer Managed Keys w/ Imported Key Material
* NO automatic rotation (key material is not generated in AWS)
* Manual rotation is the only option
* Create a new CMK -> update apps / key-alias to use the new CMK (be careful of old-key deletion)


## Using KMS with EBS

Using KMS to encrypt Elastic Block Storage (EBS) volumes.

Creating an EBS encrypted volume w/ AWS-managed key:
1. Create a new EC2
2. Provision EBS storage (not encrypted by default)
3. Turn on encryption for the attached EBS volume.
4. This will generate an AWS-managed key for EBS in KMS.
* You cannot modify/delete this AWS-managed key.

How to encrypt an existing EBS volume / the Root Device volume (default vol when launching an EC2):
1. Create an EBS volume.
2. Create a snapshot of the EBS volume.
3. Create an Amazon Machine Image (AMI) from the EBS snapshot (actions -> create image).
4. Copy the AMI to a new image -> turn on encryption -> select either AWS-managed or your own CMK.
5. Launch the AMI. Your Root Device volume will now be encrypted.


## EC2 and importing a Customer Managed Key Pair (for SSH access) - MAC USERS ONLY

1. Generate a private-key using RSA 2048 bits: 
`$ openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048`

2. Generate a public-key: 
`$ openssl rsa -pubout -in private_key.pem  -out public_key.pem`

3. Change permissions of private-key: 
`$ chmod 400 private_key.pem`

4. Go to EC2 -> Key Pairs -> Import a Key Pair -> choose your public-key. Now you can provision an EC2 instance and select your public-key.

You CANNOT take your private/public-key pair and import it into KMS.
You must follow the external Key Material import process to generate a CMK.


## EC2 and Key Pairs (SSH access)

Creating additional/multiple key pairs for an EC2 instance.
1. Provision EC2 with an original key pair + SSH into instance `$ ssh ec2-user@public-ec2-ip -i KeyPairOriginal.pem`
2. Elevate to root `$ sudo su`
3. View your public keys by:
    * `$ cat ~/.ssh/authorized_keys` where authorized_keys contains all public keys.
    * OR by calling `$ curl http://169.254.169.254/latest/meta-data/public-keys/0/openssh-key/`
4. Go to IAM -> create a new EC2 role -> provision `AmazonS3FullAccess` policy.
5. Go to EC2 -> attach new IAM role to instance.
6. Within the EC2, create a new S3 bucket: `$ aws s3 mb s3://brianec2keypairs`
7. Generate a new asymmetric key pair: `$ ssh-keygen -t rsa`
8. Add the new public key to authorized_keys `$ cat mynewkey.pub >> ~/.ssh/authorized_keys`.
9. Add the new private key to S3 bucket: `$ aws s3 cp mynewkey s3://brianec2keypairs`.
10. Go to S3 -> download new private key `mynewkey` -> `$ chmod 400 mynewkey`
11. Access the EC2 instance using the new private key `$ ssh ec2-user@ec2-public-ip -i mynewkey`

Notes about deleting Key Pairs:
* Deleting your key pair via. AWS Console will NOT prevent accessing EC2 with the private key, since the public key inside your EC2 in `~/.ssh/authorized_keys` still exists.
* If you delete an EC2 key pair via. AWS Console, you can generate a new key pair for the instance by:
    1. Go to the EC2 -> Actions -> Create an AMI.
    2. Go to AMIs -> launch the EC2 clone -> create a new key pair.
    3. Your new public key will be added to the existing list in `~/.ssh/authorized_keys`.
* Prevent access with old key pairs by removing the public keys in `~/.ssh/authorized_keys`.

Additional notes:
* You cannot use KMS with SSH for EC2 because Amazon is involved in generation of KMS keys.
* You can use CloudHSM with SSH for EC2 becausey you can export CloudHSM keys.

## AWS Marketplace Security Products

You can purchase security products from 3rd-party vendors on the AWS Marketplace.
* Includes: firewalls, hardened OS's, WAF's, Antivirus, Security Monitoring etc.
* Billed: free, hourly, monthly, annually, BYOL etc.
* Recommended reading: steps on CIS OS Hardening

## AWS Web Application Firewall (WAF) & AWS Shield

AWS Web Application Firewall (WAF): monitors/controls HTTP/HTTPS requests that are forwarded to CloudFront or an Application Load Balancer.
* Config includes: access based on IP, query string params.
* Offers 3 behaviours: (1) `ALLOW` (2) `BLOCK` (3) `COUNT`
* Additional protections based off: IP, Country, request header values, strings/regex in requests, request length, SQLi, XSS.

WAF deployment: done manually or via. CloudFormation template.
* Deploy WAF to CloudFront Distributions: global
* Deploy WAF to Application Load Balancer: region-specific

WebACL configuration example
* `CommonAttackProtectionManualIPBlockRule`: manually specify IPs to block
* `CommonAttackProtectionLargeBodyRule`: block requests w/ body size > limit
* `CommonAttackProtectionSqliRule`: block requests that indicate SQLi
* `CommonAttackProtectionXssRule`: block requests that indicate XSS

AWS Shield
* Basic-level turned on by default - $3,000/month for advanced-level.
* Advanced gives you an incident-response team + in-depth reporting.
* You won't pay if you are a victim of an attack.


## EC2 Dedicated Instances vs. EC2 Dedicated Hosts

EC2 Dedicated Instances
* Run in a VPC on dedicated physical hardware separate from other AWS accounts, for a single customer.
* Dedicated instances may share hardware with other non-dedicated instances in the same AWS account.
* Billing: per-instance basis
    * On-demand.
    * Reserved Instances - save up to 70%.
    * Spot Instances - save up to 90%.

EC Dedicated Hosts
* Also runs on dedicated physical hardware from other AWS accounts, for a single customer.
* Provides additional visibility and control over how instances are placed on a physical server.
* Consistently deploy instances to the same physical server each time.
* Enable you to use your existing server-bound software licenses (e.g. VMWare, Oracle licenses which might require dedicated hosts).
* Enable you to address corporate and regulatory compliance.
* Billing: per-host billing

Provision Dedicated Instances / Dedicated Hosts via. EC2 service when launching an instance.


## AWS Hypervisors, Isolation of AWS Resources, AWS Firewalls

AWS Hypervisor
* Hypervisor or virual machine monitor (VMM) is software, firmware, hardware that creates an runs virutal machines.
    * Host machine: a computer on which a hypervisor runs 1+ virtual machines
    * Guest machine: each virtual machine
* EC2 runs on __Xen Hypervisors__: they can have guest OSs' running Paravirtualisation (PV) or using Hardware Virtual Machine (HVM).
    * HVM guests are fully virtualised: VMs on top of hypervisors are not aware that they are sharing processing time with other VMs.
    * PV is a lighter form of virtualisation and it used to be quicker.
    * Performance gap between HVM/PV is closed and AWS recommends using HVM over PV.
    * Windows EC2 instances can only be HVM where Linux can be HVM/PV.
* Paravirtualised guests
    * Relies on the hypervisor to provide support for operations that normally require privileged access.
    * Guest OS has no elevated access to the CPU.
    * CPU provides 4 separate privilege modes: 0-3 __"rings"__.
    * Host OS executes in __Ring 0__
    * Guest OS runs in lesser-privileged __Ring 1__ and applications in least-privileged __Ring 3__
    * E.g. `R0: Xen Hypervisor` | `R1: Linux instance` | `R3: Applications`

What happens when we interact with EC2:
1. Physical Interface
2. Firewall splits traffic (runs at Hypervisor-layer - AWS managed)
3. Traffic is split and isolated through our security groups, our virtual interface, the hypervisor back to our resources.

Hypervisor Access (by AWS employees)
* Administrators with a business need to access the management plane requires MFA to access the administration hosts.
* The administration hosts are systems that are specifically designed, built, configured and hardened to protect the management plane of the cloud.
* All access is logged and audited.
* When an employee no longer has business need to access the management plane, privileges and access to these hosts can be revoked.

Guest OS (EC2) Access (by customers)
* These virtual instances are controlled completely by customers.
* Full root access over accounts, services and applications running on the EC2.
* AWS have no access rights to our Guest OS in EC2.

Memory Scrubbing:
* EBS automatically resets every block of storage used by the customer, so one customer's data is never unintentionally exposed to another customer. (all storage and RAM memory)
* Memory allocated to guests is scrubbed/zeroed by the Hypervisor when it is unallocated to a guest.
* Memory is not returned to the pool of free memory available for new allocations until scrubbing is complete.
* I.e. disk-recovery tools to find other customer's data won't work.

## KMS Grants

KMS Grants are an alternate access control mechanism to a Key Policy
* Programtically delegate use of KMS CMKs to other AWS principals (another user in your account / another account)
* Provide temp granular permissions (encrypt, decrypt, re-encrypt, describekey etc.)]
* Only grants ALLOWs, not DENYs
* Use Key Policies for static permissions, Grants for temp permissions.
* _Analogy: I give house keys to a friend to take care of my plants while I'm on holidays._

KMS Grants are configure programatically via CLI
* _create-grant_: adds new grant to CMK, specifies who can use it and list of operations the grantee can perform. A grant token is generated and can be passed as an argument to a KMS API.
* _list-grants_: lists grants
* _revoke-grant_: remove a grant

Example: Providing "Encrypt" operation as grant to IAM user
```bash
#Create a new key and make a note of the region you are working in 
aws kms create-key

#Test encrypting plain text using my new key: 
aws kms encrypt --plaintext "hello" --key-id <key_arn>

#Create a new user called Dave and generate access key / secret access key
aws iam create-user --user-name dave
aws iam create-access-key --user-name dave

#Run aws configure using Dave's credentials creating a CLI profile for him
aws configure --profile dave
aws kms encrypt --plaintext "hello" --key-id <key_arn> --profile dave

#Create a grant for user called Dave
aws iam get-user --user-name dave
aws kms create-grant --key-id <key_arn> --grantee-principal <Dave\'s_arn> --operations "Encrypt"

#Encrypt plain text as user Dave: 
aws kms encrypt --plaintext "hello" --key-id <key_arn> --grant-tokens <grant_token_from_previous_command> --profile dave

#Revoke the grant:
aws kms list-grants --key-id <key_arn>
aws kms revoke-grant --key-id <key_arn> --grant-id <grant_id>

#Check that the revoke was successful:
aws kms encrypt --plaintext "hello" --key-id <key_arn> --profile dave

https://docs.aws.amazon.com/cli/latest/reference/kms/create-grant.html
```

## KMS Policy Conditions - ViaService

Policy Conditions can be used to specify a condition within a Key Policy or IAM Policy

KMS provides a set of predefined __Condition Keys__.
* See https://docs.aws.amazon.com/kms/latest/developerguide/policy-conditions.html.

Use __kms:ViaService__ to allow or deny access to your CMK according to which service the request originated from.
* Only for services that are integrated with KMS e.g. S3, EBS, RDS, Systems Manager, SQS, Lambda

ViaServive example: CMK may be used for "Encrypt" action ONLY if request comes from EC2/RDS from the specified regions
```json
"Effect": "Allow",
"Principal": {
    "AWS": "arn:xxx:xxx:xxx/ExampleUser"
},
"Action":[
    "kms:Encrypt",
]
"Resource":"*",
"Condition":{
    "StringEquals":{
        "kms:ViaService":[
            "ec2.us-west-2.amazonaws.com",
            "rds.us-west-2.amazonaws.com",
        ]
    }
}
```

## KMS Cross Account Access for CMKs

2 steps to provide cross-account access.
* Example: Users in account HELLO need to use a CMK in account WORLD
1. Change the Key Policy for the CMK in account WORLD to allow ROOT USER in HELLO to have access. (doesn't have to be root account, can specify a specific user/role ARN instead)
2. Set up an IAM user/role in HELLO with explicit permission to use the CMK in WORD.

Example IAM policy in account HELLO for cross account access to CMK in WORLD
```json
{
    "Statement":[
        {
            "Sid": "AllowUseOfCMKInAccountWORLD",
            "Effect": "Allow",
            "Action":[
                "kms:Encrypt",
                "kms:Decrypt",
                "kms:ReEncrypt*",
            ],
            "Resource": "arn:aws:kms:us-west-2:WORLD:key/guid"
        }
    ]
}
```
