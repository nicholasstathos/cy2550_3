1.1


-pbkdf2 is an instruction to openssl to use password based key derivation function 2 which makes the passphrase we just added into a cryptographic key. I need it to avoid taking the passphrase directly, instead inputting to AES-256.


1.2

Salts are randomly picked with each run. Because the key and IV are derived from passphrase + salt they all get a different IV. 

If both files are identical encryption can have an input easily paired to an output, which would make it deterministic. This makes equality easy to spot. 

1.3

1. **ECB produced 3 distinct blocks, and the most common block repeated 24 times. CBC produced 37 distinct blocks, each appearing once.**

2. **ECB leaked the pattern and frequency of repeated text blocks, allowing an attacker to infer info abt the plaintext without knowing the key.**

3. **I would ask what encryption mode is being used, bc AES alone doesnt tell me if repeated data patterns are protected.**

-----------------------------------------------------------------
2. 

# SHA-256 vs HMAC

1. Why SHA-256 doesn't protect your colleague:
SHA-256 checks if data changed and doesnt care who sent it. An attacker in the middle changes the file and then generates a new SHA-256 hash for it. They can send both. Your colleague hashes the fake file and then it matches the fake hash. In this situation the check still passes

2. What changes with HMAC:
HMAC uses a secret key shared directly between you and a colleague securely. An attacker cant generate a valid hash for a modified file without knowing this key.

3. 

SHA-256
They can read the file, modify the file, generate a new hash for it, and trick your colleague.
They cant find a fake file that produces the exact original hash bc collisions are practically impossible.

HMAC
- Can read the file, modify or delete the file, and cause the download to fail.
- Cant create a valid HMAC tag for a modified file, figure out the secret key, or trick counterpart into accepting bad data.
------------------------------------------------------------------------------------
3. 

Email verification confirms that the user has access to the email in question, not real world verification. It also doesn't mean this is the sole user of the account or the owner of the private key.

Classmate and I meet in person, at which point classmate reads off their machine and we compare gpg -- fingerprint's 40 characters to their 40 characters. This works because its out of band, like One Time Pad. Doing anything over the network could be spoofed by the attacker here. 
------------------------------------------------------------------------------------
4.2: 


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

Generated with Claude Opus 5.5 "Write me a python script that encrypts a file w AES" 

** Issues with my Claude-Derived code ** 

- AES only protects data between parties who already share a key. It can't prove who sent a message, set up that key safely, or detect a replayed message. This means an attacker could misrepresent themselves. 
- Empty or Simple passwords like 'password' are accpeted. We discussed brute force attacks that an attacker could easily use to guess password.
- No Sender Identity so Non-Repudiation is impossible. This means that an attacker could send infortmation without being identified.  
- Nothing binds files to current context so older files or different valid ones can be swapped in. This means that an attacker could stage a replay attack, which we breifly discussed in class and I researched while investigating problems with my code.



Fixes:
- Password Validation, this addresses empty passwords and brute force attacks.
- Sender Signatures, this allows for Non-Repudiation which was a significant issue I pointed out before. 
- I added context binding to thwart any possible replay attack like I mentioned.

Screenshots of the fixed demo are in the submitted document. 
