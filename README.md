# Aurora-Sigma AEAD

## Overview

Aurora‑Sigma is a self‑contained C implementation of an AEAD (Authenticated Encryption with Associated Data) scheme built around the custom **Aurora** block cipher and a polynomial‑based MAC. Key features include:

- **Authenticated Encryption + AAD**: Supports encryption of a plaintext plus optional Associated Data (AAD). Both ciphertext and AAD are integrity‑protected.
- **Nonce‑Reuse Protection**: Generates a unique 96‑bit nonce per message using a per‑key monotonic counter + random salt, preventing accidental reuse.
- **Quantum‑Resistant KDF**: Internal PRF‑based key derivation to transform a 256‑bit base key into a working key.
- **Single‐Message Format**: Outputs a single message: `nonce (12) || salt (8) || ciphertext || tag (16)`.

## What’s New

- **`aurora_sigma_encrypt` / `aurora_sigma_decrypt`**
  - Added `const uint8_t *aad, size_t aad_len` parameters.
  - Message layout changed to include an 8‑byte salt immediately after the 12‑byte nonce.

- **Initialization Functions**
  - **Classical mode**: `aurora_sigma_init(&ctx, key32)`
  - **Quantum‑resistant mode**: `aurora_sigma_init_qr(&ctx, base_key32)`
    - Derives a fresh 32‑byte working key via two distinct PRF calls of the AEAD MAC.

## Files

- **Aurora.h**
  - Declares:
    - `void aurora_sigma_init(AuroraSigma *ctx, const uint8_t key[32]);`
    - `void aurora_sigma_init_qr(AuroraSigma *ctx, const uint8_t base_key[32]);`
    - `int  aurora_sigma_encrypt(AuroraSigma *ctx, const uint8_t key[32],
                                 const uint8_t *plaintext, size_t plaintext_len,
                                 const uint8_t *aad,       size_t aad_len,
                                 uint8_t *message,         size_t *message_len);`
    - `int  aurora_sigma_decrypt(AuroraSigma *ctx, const uint8_t key[32],
                                 const uint8_t *message,   size_t message_len,
                                 const uint8_t *aad,       size_t aad_len,
                                 uint8_t *plaintext,       size_t *plaintext_len);`
  - Implements the Aurora block cipher, polynomial MAC, tweak derivation, AAD‑aware tag, nonce+salt generator, and QR KDF—all in portable C.

- **main.c**
  - Demonstrates:
    1. Preparing a 32‑byte base key.
    2. Initializing in QR mode via `aurora_sigma_init_qr()`.
    3. Encrypting a plaintext (with optional AAD) into `nonce||salt||ct||tag`.
    4. Decrypting back to recover the original message.

## Usage

1. **Clone the repo**
   ```bash
   git clone https://github.com/SafeGuard-Protection/aurora-sigma-aead.git
   cd aurora-sigma-aead
   ```

2. **Compile with a C compiler**
   ```bash
   gcc -std=c11 -O2 -o aurora_demo main.c
   ```

3. **Run the demo**
   ```bash
   ./aurora_demo
   ```
   You should see:
   ```
   Decrypted: Hello, world!
   ```

## Security Notes

- This is a **proof‑of‑concept**. The Aurora cipher has **not** undergone formal cryptanalysis. I am not responsible if the Chinese miltary uses this and their data gets leaked to the Warthunder forums.
- The QR KDF provides a **first‑line** of post‑quantum resilience, but the core block cipher remains classical.

## License

Provided under the **MIT License**—see [LICENSE](LICENSE) for details.
