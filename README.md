This protocol is a software package, including a graphical interface under React js, a Rust backend under Tauri and a sqlite3 database that stores the secrets (data the user wishes to encrypt). It combines several cryptographic primitives such as AEAD mode GCM, Argon 2, SHA-256, which together ensure data integrity and confidentiality. Features include

**F1 - Authentication:** 
To use the software, users must authenticate themselves by providing their password.

**F2 - Secret manager:**
After authentication, the user is taken to a page where he can manage all the secrets stored in the database. Each secret character is hidden by a star. In the manager, the user can view the original text (decrypt), add, copy, delete and modify a secret.

## Security
The cryptographic primitives mentioned above are introduced into the protocol and used to perform the following operations:

1. Key derivations:
The password in the system is called the “Master Key”, it is data that is hashed with the Argon 2 hashing function to generate 2 new keys K1 and K2 which are used for encryption and decryption of certain sensitive parameters and all secrets.

2. Encryption of sensitive parameters:
Among the parameters used by AEAD-GCM, only one is encrypted, the DA (Data Associated), a parameter that ensures the integrity of secrets. It is encrypted under AEAD-GCM with the derived key K1, a unique nonce to unlock this parameter and without DA. If an attacker finds this parameter, he can easily retrieve the original text and modify the secrets. Parameters such as the unique nonces for each secret and the nonce to unlock the DA parameter are stored in the database without being encrypted.

3. Secrets:
As explained earlier, secrets are information that the user wishes to encrypt. When a user adds a secret, the derived key K2 and the decrypt DA will be used in the AEAD-GCM primitive to encrypt it. When the user decrypts the information, it will be visible for 15 seconds, after which it will be encrypted again. When a secret is modified, the user will not see the secret; the new modification overwrites the previous one without a decryption operation of the previous secret.

4. The database:
In the database, less sensitive information, such as the nonce, is stored unencrypted, but more sensitive information, such as secrets and the DA, is stored encrypted.

5. Memory:
To prevent malicious software from easily retrieving decrypted or encrypted information from the machine's memory, very little data will be stored in the buffer.
