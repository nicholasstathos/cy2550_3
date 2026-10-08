1. **ECB produced 3 distinct blocks, and the most common block repeated 24 times.**

2. **ECB leaked the pattern and frequency of repeated text blocks, allowing an attacker to infer info abt the plaintext without knowing the key.**

3. **I would ask what encryption mode is being used, bc AES alone doesnt tell me if repeated data patterns are protected.**

-----------------------------------------------------------------
2. 

# SHA-256 vs HMAC

1. Why SHA-256 doesn't protect your colleague:
SHA-256 checks if data changed and doesnt care who sent it. An attacker in the middle changes the file and then generates a new SHA-256 hash for it. They can send both. Your colleague hashes the fake file and then it matches the fake hash. In this situation the check still passes

2. What changes with HMAC:
HMAC uses a secret key shared only between you and your colleague. An attacker cannot generate a valid hash for a modified file without knowing that key.

3. 

SHA-256
They can read the file, modify the file, generate a new hash for it, and trick your colleague.
They can’t find a fake file that produces the exact original hash bc collisions are practically impossible.

HMAC
- Can read the file, modify or delete the file, and cause the download to fail.
- Cant create a valid HMAC tag for a modified file, figure out the secret key, or trick your colleague into accepting bad data.

------------------------------------------------------------------------------------
4. 


1. What is contained in each packet:
   - Pubkey enc: A random AES session key locked with the person its sent to RSA public key.
   - Encrypted data : actual message content locked by AES session key.

2. Why GPG uses this approach:
   - RSA is too slow and heavy for whole files and  AES handles big files almost instantly.
   - RSA cant directly encrypt anything larger than its own key size.

3. Name of this construction:
   It is Hybrid Encryption.
4.3:

1. Which key is used for signing?
   - The sender's private key.

2. Which key is used for verifying?
   - The sender's public key.

3. Which key is used for encryption?
   - The recipient's public key.

4. Which key is used for decryption?
   - The recipient's private key.

5. What is one security property provided by signing that encryption does not include?
   - Non-repudiation bc it proves who sent the message, whereas encryption alone only keeps the data private.
--------------------------------------------------------------------------------------
5.

Ed25519 uses elliptic curve cryptography that provides much stronger security per bit of key length than RSA's factorization-based math. As a result, a 256-bit Ed25519 key delivers roughly equivalent cryptographic strength to a 3072-bit or 4096-bit RSA key while remaining a lot smaller and a lot faster.


7. 

** Issues with my Claude-Derived code ** 

- AES only protects data between parties who already share a key. It can't prove who sent a message, set up that key safely, or detect a replayed message.
- Empty or Simple passwords like 'password' are accpeted
- No Sender Identity so Non-Repudiation is impossible 
- Nothing binds files to current context so older files or different valid ones can be swapped in

