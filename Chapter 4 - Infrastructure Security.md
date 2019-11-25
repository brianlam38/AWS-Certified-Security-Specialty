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
