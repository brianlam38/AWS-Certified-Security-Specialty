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

