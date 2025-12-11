
# CSCG 2024: Crypto Challenge Writeup – “Once-in-Nonce”

## Challenge Overview

This challenge presented an encryption oracle using a stream cipher, most likely AES in CTR mode or a similar construction. The oracle accepted user-controlled input and returned the encrypted output — all while reusing the same nonce.

This nonce reuse turned out to be the core vulnerability. The objective was to exploit this flaw to decrypt an unknown ciphertext and recover the flag.

---

## Why “Once-in-Nonce” Matters

In stream ciphers like AES-CTR:

- A random key and nonce generate a **keystream**
- This keystream is **XOR’d with the plaintext** to produce ciphertext
- If the **same nonce is reused**, the **same keystream** is used
- If a known plaintext is XOR’d with the resulting ciphertext, the keystream can be recovered
- Once the keystream is known, **any ciphertext encrypted under the same key and nonce can be decrypted**

This vulnerability is fatal when the attacker controls input and can observe the ciphertext output — i.e., a **chosen-plaintext attack**.

---

## Step-by-Step Exploitation

### 1. Leaking the Keystream

I submitted a known input to the oracle — a string of repeated characters (e.g., `'A' * 64`). Since I knew the exact plaintext and could observe the ciphertext, I computed the keystream using:

```
keystream = xor(known_plaintext, ciphertext)
```

This gave me a portion of the keystream.

### 2. Keystream Length Matters

My early attempts used short inputs (like 32 or 48 bytes), which resulted in partial keystreams — enough to decrypt only part of the flag. The output would look like this:

```
CSCG{turns_out_that_once_in_nonc�B��nOK...}
```

Eventually, I increased the input length to 64 bytes (128 hex characters). This gave me a full-length keystream long enough to decrypt the entire flag.

### 3. Decrypting the Flag

Once I had the full keystream, I XOR’d it with the unknown ciphertext to recover the plaintext:

```
plaintext = xor(ciphertext, keystream)
```

After correcting the keystream size, the decrypted output was valid ASCII and completed the flag.

> ⚠️ The full flag is omitted from this writeup to avoid spoilers for other participants.

---

## Key Takeaways

- **Nonce reuse in stream ciphers is devastating**: It allows full keystream recovery and thus decrypts all ciphertexts under that nonce.
- **Chosen-plaintext attacks** become trivially effective when nonce reuse is present.
- **Keystream length must match the ciphertext length** for full decryption.
- XOR-ing known plaintext with its ciphertext gives the keystream. XOR-ing that keystream with another ciphertext gives the original plaintext.

---

## Lessons Learned

- “Never use the same nonce twice” is not just advice — it’s critical to cryptographic security.
- Even without knowledge of the key, **keystream recovery makes decryption possible**.
- A short or partial input can lead to misinterpreting results — so always match or exceed expected output length.
- Partial flags like `CSCG{...}` can hint at progress and help tune exploit parameters.

---

## Vulnerability Fix & Mitigation

To fix this issue:

- **Never reuse a nonce** when using stream ciphers like AES-CTR or ChaCha20.
- Use **unique nonces** for every encryption operation — either randomly generated or monotonically increasing (with proper counter management).
- If determinism is required, **use authenticated encryption schemes like AES-GCM**, which protect against keystream reuse and offer integrity guarantees.

---

## Conclusion

This challenge was a strong reminder of how catastrophic stream cipher misuse can be. It provided a hands-on opportunity to exploit a real-world vulnerability and deepen my understanding of cryptographic implementation flaws.
