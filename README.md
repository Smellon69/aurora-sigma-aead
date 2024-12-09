# Aurora-Sigma AEAD

## Overview

Aurora-Sigma is a custom AEAD construction created by my friend, **rot32**. It aims to show the structure of an authenticated encryption scheme:

- **Authenticated Encryption**: Ensures that both confidentiality (encryption of the plaintext) and integrity (detection of tampering) are provided.
- **No Associated Data**: This does not use associated data. The entire message (including the internally generated nonce) is protected by the authentication tag.
- **Single-Message Interface**: The encryption function returns a single message consisting of `nonce || ciphertext || tag`. The decryption function only requires the secret key and this combined message to recover the original plaintext and verify integrity.

## What This Code Does

- **Key Schedule and Block Cipher**: A custom block cipher (128-bit blocks, 256-bit key) with substitution (S-box), diffusion (MDS matrix), and a simple Feistel-based key schedule.
- **GF(2^128) MAC Computation**: A polynomial-based MAC over Galois Field operations to produce the authentication tag.
- **Nonce Generation**: The nonce is generated automatically during encryption and placed at the start of the output message.
- **Integrity of Entire Message**: If any byte of the nonce, ciphertext, or tag is altered, decryption will fail.

## Files

- **Aurora.h**:  
  The header file containing the `AuroraSigma` class and all necessary functions (block cipher, MAC, etc.).  
  Key points:
  - `AuroraSigma` class provides `encrypt()` and `decrypt()` functions.
  - `encrypt()` returns a single vector containing `nonce || ciphertext || tag`.
  - `decrypt()` takes the key and the combined message to recover plaintext.

- **main.cpp**:  
  A demonstration of how to:
  - Generate a key (randomly generated in this example).
  - Encrypt a plaintext message into `nonce || ciphertext || tag`.
  - Decrypt on the "server" side using just the key and the received message.

## Usage

1. **Clone the repository.**
   
   ```bash
   git clone https://github.com/SafeGuard-Protection/aurora-sigma-aead.git
   cd aurora-sigma-aead
   ```

2. **Compile using a modern C/C++ compiler:**
   
   ```bash
   g++ -std=c++17 -O2 -o aurora_demo main.cpp
   ```

3. **Run the executable:**
   
   ```bash
   ./aurora_demo
   ```
   
   You will see the encryption and decryption in action.

## License

This code is provided as-is, with **no warranty**, under the MIT license. Refer to the [LICENSE](LICENSE) file for more details.

---

Created by **rot32**, shoutout to him.
