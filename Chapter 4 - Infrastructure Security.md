# Infrastructure Security

## AWS Key Management Service (KMS)

KMS is a managed service that makes it easy for you to create and control the encryption keys used to encrypt your data + uses Hardware Security Modules (HSMs) to protect the security of your keys.

*KMS is region-specific.*

Customer-Master-Keys (CMK)
* Is a logical representation of a master key, typically used to generate/encrypt/decrypt *Data Keys* used to encrypt your actual data - this practice is known as *Envelope Encryption*.
* You cannot delete CMKs immediately, only disable them with a 7-30 day waiting period before deletion.
* There are three types of CMKs:
    1. Customer managed CMKs - customer owned / imported keys in your account (full control)
    2. AWS managed CMKs - AWS managed keys in your account that are associated with an AWS service
    3. AWS owned CMKs - AWS owned keys that are NOT in your account for securing data in multiple AWS accounts (no control)

Importing an External Key into KMS
1. Create a customer-managed CMK by selecting "External" for the key material origin - it won't be useable yet.
2. Import key material - select Wrapping Algorithm SHA1
3. Import key material - download Wrapping Key as `PublicKey.bin` and the Import Token `ImportTokenxxx`
4. Click "I am ready to upload my exported key material"
5. Use `openssl` and follow instructions here to generate key material: https://docs.aws.amazon.com/kms/latest/developerguide/importing-keys-encrypt-key-material.html
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
6. Upload `EncryptedKeyMaterial.bin` and `ImportTokenxxx`.
7. The key is now available for use.

More info on importing an External Key
* You CANNOT use the same `EncryptedKeyMaterial` and `ImportToken` files twice - it is SINGLE USE only.
^The downloaded Wrapping Key used to encrypt the openSSL-generated key is associated with the `ImportToken`.
* You CANNOT *enable automatic key rotation* for a CMK with imported key material.
* You CAN *manually rotate* a CMK with imported key material.
^Do this by creating a new CMK then import the new key material into that CMK (i.e. repeat the same process as creating a new key)
* Ciphertexts are not portable between CMKs.
* You can delete imported keys immediately by deleting the Key Material.

