## Changelog

Welcome to the **QuarkDash Crypto** changelog.
Here you can find information about all stable algorithm versions.

## v.1.2.1 (LTS Public)
> **This is an official port of QuarkDash Crypto encryption protocol** for Golang. Original protocol is written on Typescript

**🔐 Critical security and compatibility fixes (to ensure everything decrypts and signs correctly):**
- **SHA-256/SHA-512 hashes**: used in Go implementation from system libraries.
- **SHAKE-256 hash**: used in Go implementation from system libraries.
- **Key Derivation Formula (KDF)**: a fatal bug was identified and fixed: previously, when requesting a long key, the function would enter an infinite loop and return zeros. Now it works as intended: it sequentially generates hash chunks, mixing them with salt and data (following the HKDF principle).
- **Post-quantum exchange (NTT) mathematics:** fixed the "roots" (special numbers used to multiply polynomials). We've implemented a proper fast transformation algorithm (bit-reversible Cooley-Tukey). This necessitated a change in the ciphertext size: it now takes up a precise **544 bytes** (512 bytes of data + 32 bytes of hint). Old 512-byte messages will no longer pass verification, so compatibility with the previous version has been intentionally broken - for the sake of correctness.

**🤝 Fixes to symmetric key exchange (so that both parties receive the same key):**
- **Salt for session keys:** previously, when creating a shared key, each participant generated a random salt. This resulted in different encryption keys. **This has been fixed:** the salt is now strictly fixed (32 zeros), so both clients output identical ``sessionKey`` and ``macKey``.
- **An error occurred in the finalization of the exchange:** the wrong public key was used when calculating the shared secret. This has been fixed; now both parties hash the same recipient's public key, and the secret is converged.
- **Rekeying sequence (Key rotation):** the steps have been reversed. Now, when updating keys, encryption occurs first (with the old key), and only then is the new one deduced. This ensures that the intermediate token can be decrypted with the old keys on both sides, avoiding desynchronization.

This version has stabilized the algorithm and significantly accelerated its performance.

**This version is now available as an LTS solution for your projects.**