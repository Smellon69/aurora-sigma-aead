#include <stdint.h>
#include <stddef.h>
#include <time.h>
#include <stdlib.h>  // For rand, srand only

/*
 * Aurora-Sigma AEAD (Conceptual Demonstration)
 *
 * This code demonstrates an Authenticated Encryption with Associated Data (AEAD)
 * scheme built on top of a custom block cipher ("Aurora") and a polynomial-based
 * MAC approach.
 *
 * WARNING: This is purely a conceptual demonstration. The block cipher, S-boxes,
 * MDS matrices, GF(2^128) multiplication, and other details are not proven secure.
 * DO NOT USE THIS CODE IN PRODUCTION.
 * 
 * Key points:
 * - No associated data.
 * - Caller-provided buffers (no malloc/free).
 * - No use of high-level standard library memory functions.
 * - Nonce generated internally in encrypt().
 * - The entire message is integrity-protected.
 */

 /****************************************
  * Utility Functions (No memset/memcpy)
  ****************************************/

/**
 * @brief Set an array of bytes to 0.
 * @param arr Byte array to zero.
 * @param len Length of the array.
 */
static void zero_bytes(uint8_t* arr, size_t len) {
    size_t i;
    for (i = 0; i < len; i++) {
        arr[i] = 0;
    }
}

/**
 * @brief Copy bytes from src to dest (like memcpy but with a loop).
 * @param dest Destination array.
 * @param src Source array.
 * @param len Number of bytes to copy.
 */
static void copy_bytes(uint8_t* dest, const uint8_t* src, size_t len) {
    size_t i;
    for (i = 0; i < len; i++) {
        dest[i] = src[i];
    }
}

/**
 * @brief Store a 32-bit value in big-endian format into a byte array.
 * @param p Byte array (at least 4 bytes).
 * @param v 32-bit integer value.
 */
static inline void store_be32(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

/**
 * @brief Store a 64-bit value in big-endian format into a byte array.
 * @param p Byte array (at least 8 bytes).
 * @param v 64-bit integer value.
 */
static inline void store_be64(uint8_t* p, uint64_t v) {
    int i;
    for (i = 7; i >= 0; i--) {
        p[i] = (uint8_t)(v & 0xff);
        v >>= 8;
    }
}

/**
 * @brief XOR two 16-byte blocks: x = x ^ y
 * @param x Input/Output block (16 bytes).
 * @param y Input block (16 bytes).
 */
static inline void xor_block(uint8_t x[16], const uint8_t y[16]) {
    int i;
    for (i = 0; i < 16; i++) x[i] ^= y[i];
}

/****************************************
 * GF(2^8) Arithmetic & S-box & MDS
 ****************************************/

 /**
  * @brief Multiply two bytes in GF(2^8) with the given polynomial reduction.
  *
  * This uses a polynomial-based multiplication with 0x8d as a reduction polynomial.
  */
static inline uint8_t gf_mul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    int i;
    for (i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        {
            uint8_t hi = (uint8_t)(a & 0x80);
            a <<= 1;
            if (hi) a ^= 0x8d; // reduction polynomial
        }
        b >>= 1;
    }
    return p;
}

/**
 * @brief A S-box (Substitution box).
 */
static const uint8_t SBOX[256] = {
    0x3a,0xf7,0xb2,0x0e,0xc1,0x95,0x4d,0x6f,0xde,0x24,0x82,0x7b,0x14,0xd9,0x2c,0x48,
    0x99,0xd3,0xab,0x81,0x4e,0x1f,0x37,0xa2,0x6a,0x0c,0x5e,0x21,0xee,0x92,0x73,0xbd,
    0x0b,0x5f,0xd8,0x4a,0x23,0x39,0x67,0xcc,0x85,0x9a,0xfc,0x11,0x42,0x17,0x78,0x8e,
    0x2d,0xe3,0x9c,0x53,0xf8,0xae,0xc4,0x62,0x0f,0x7f,0x4b,0x96,0x5b,0xdd,0x29,0xf1,
    0x63,0xb1,0x16,0x3c,0x89,0xeb,0xc3,0x51,0x2a,0x72,0x45,0x1b,0x98,0x36,0xa9,0xc7,
    0x6d,0x5a,0xb4,0xe4,0xd6,0xfa,0x8c,0x25,0x0d,0x7c,0xf9,0x8a,0x13,0xaf,0x3b,0x90,
    0x3e,0x57,0x60,0x9d,0xca,0xa6,0x1a,0xb8,0x7a,0x06,0x20,0xdf,0x1e,0x4f,0xed,0x8f,
    0xa3,0x40,0xbe,0x4c,0x9f,0x68,0x02,0x76,0xd0,0x50,0x59,0x1c,0x31,0xb7,0xea,0x94,
    0x6e,0x08,0xa5,0x26,0xce,0x80,0x9b,0x2f,0xf3,0x5d,0x33,0x49,0x8d,0x7d,0xbc,0x65,
    0x10,0xd2,0x27,0x56,0x61,0x6c,0x30,0xfe,0x03,0xdf,0x54,0xaa,0xc8,0x75,0x83,0x19,
    0x46,0xf2,0x34,0x09,0x5c,0x0a,0xad,0x38,0x52,0x7e,0xfb,0x66,0x87,0xa0,0x55,0xe2,
    0x12,0x15,0x93,0x2b,0x77,0xcd,0xb3,0x84,0xcf,0x9e,0x71,0x58,0x5f,0x79,0xe1,0x6b,
    0xfd,0xba,0x1d,0xb0,0x88,0x8b,0xa8,0x43,0x4e,0x74,0x07,0x2e,0xb9,0xd4,0x00,0x91,
    0x44,0x1f,0xdb,0xac,0xef,0xc5,0x50,0x05,0x18,0x9c,0xe0,0x04,0x3d,0xc9,0xf4,0x28,
    0xb5,0xc2,0x2a,0x41,0xd7,0xae,0x7f,0x69,0xec,0xa4,0xc6,0xf5,0x86,0x32,0x97,0x64,
    0xda,0xc0,0xe8,0xbe,0x35,0x70,0xf6,0x22,0x9c,0xb6,0x55,0xa1,0xd1,0x08,0x4d,0x5f
};

/**
 * @brief MDS matrix for a linear diffusion layer.
 *
 * MDS stands for Maximum Distance Separable matrix,
 * commonly used in block ciphers to provide good diffusion.
 */
static const uint8_t MDS[16] = {
    0x01,0x01,0x01,0x01,
    0x02,0x05,0x09,0x1f,
    0x04,0x19,0x81,0x7d,
    0x08,0xb3,0xa6,0x54
};

/**
 * @brief Multiply state by MDS matrix (column mixing).
 *
 * This performs a linear mixing operation.
 */
static inline void mds_mul(uint8_t state[16]) {
    uint8_t tmp[16];
    int i;
    for (int c = 0; c < 4; c++) {
        uint8_t col[4];
        for (int r = 0; r < 4; r++) col[r] = state[r * 4 + c];
        for (int r = 0; r < 4; r++) {
            uint8_t val = 0;
            for (int k = 0; k < 4; k++) {
                val ^= gf_mul(col[k], MDS[r * 4 + k]);
            }
            tmp[r * 4 + c] = val;
        }
    }
    for (i = 0; i < 16; i++) state[i] = tmp[i];
}

/****************************************
 * Key Schedule
 *
 * Derives round keys from the given master key.
 * This is a conceptual, toy key schedule.
 ****************************************/

 /**
  * @brief Apply round function to a block using S-box and MDS, then XOR round constant.
  * @param block 16-byte block
  * @param rc round constant
  */
static void round_func(uint8_t block[16], uint8_t rc) {
    int i;
    // SubBytes
    for (i = 0; i < 16; i++) block[i] = SBOX[block[i]];
    // MDS
    mds_mul(block);
    // Add round constant
    block[0] ^= rc;
}

/**
 * @brief Aurora key schedule.
 * @param key 32-byte master key.
 * @param roundKeys Output: 11 round keys, each 16 bytes.
 */
static inline void aurora_key_schedule(const uint8_t key[32], uint8_t roundKeys[11][16]) {
    uint8_t KL[16], KR[16];
    int i;
    for (i = 0; i < 16; i++) KL[i] = key[i];
    for (i = 0; i < 16; i++) KR[i] = key[16 + i];

    // Generate 11 round keys:
    // For this toy cipher, we do a simple Feistel-like mixing 
    // and store intermediate values.
    for (int r = 0; r < 11; r++) {
        // Current round key = KL ^ KR
        for (i = 0; i < 16; i++) roundKeys[r][i] = (uint8_t)(KL[i] ^ KR[i]);

        if (r < 10) {
            uint8_t temp[16];
            for (i = 0; i < 16; i++) temp[i] = KR[i];
            round_func(temp, (uint8_t)r);
            for (i = 0; i < 16; i++) {
                uint8_t newR = (uint8_t)(KL[i] ^ temp[i]);
                KL[i] = KR[i];
                KR[i] = newR;
            }
        }
    }
}

/****************************************
 * Block Cipher "Aurora"
 *
 * This block cipher is a conceptual design.
 * It uses 11 round keys, S-boxes, ShiftRows, MDS mixing, etc.
 ****************************************/

typedef struct {
    uint8_t roundKeys[11][16];
} AuroraBlock;

/**
 * @brief SubBytes step for encryption round.
 * @param state 16-byte state block.
 */
static inline void sub_bytes(uint8_t state[16]) {
    int i;
    for (i = 0; i < 16; i++) state[i] = SBOX[state[i]];
}

/**
 * @brief ShiftRows step.
 *
 * Rearranges bytes in each row to provide further diffusion.
 */
static inline void shift_rows(uint8_t state[16]) {
    uint8_t tmp[16];
    int i;
    for (i = 0; i < 16; i++) tmp[i] = state[i];

    // Simple shift pattern, it works.
    state[0] = tmp[0];   state[1] = tmp[1];   state[2] = tmp[2];   state[3] = tmp[3];
    state[4] = tmp[5];   state[5] = tmp[6];   state[6] = tmp[7];   state[7] = tmp[4];
    state[8] = tmp[10];  state[9] = tmp[11];  state[10] = tmp[8];  state[11] = tmp[9];
    state[12] = tmp[15]; state[13] = tmp[12]; state[14] = tmp[13]; state[15] = tmp[14];
}

/**
 * @brief Add a round key to the state (XOR).
 * @param state 16-byte state.
 * @param rk 16-byte round key.
 */
static inline void add_round_key(uint8_t state[16], const uint8_t rk[16]) {
    int i;
    for (i = 0; i < 16; i++) state[i] ^= rk[i];
}

/**
 * @brief Initialize the Aurora block cipher with a given 32-byte key.
 * @param blk AuroraBlock structure to initialize.
 * @param key 32-byte key.
 */
static void aurora_block_init(AuroraBlock* blk, const uint8_t key[32]) {
    aurora_key_schedule(key, blk->roundKeys);
}

/**
 * @brief Encrypt one 16-byte block with Aurora block cipher.
 * @param blk AuroraBlock context (has round keys).
 * @param in 16-byte plaintext block.
 * @param out 16-byte ciphertext block.
 */
static void aurora_block_encryptBlock(const AuroraBlock* blk, const uint8_t in[16], uint8_t out[16]) {
    uint8_t state[16];
    int i;
    for (i = 0; i < 16; i++) state[i] = in[i];

    // Initial round key addition
    add_round_key(state, blk->roundKeys[0]);

    // 10 rounds
    for (int r = 1; r <= 10; r++) {
        sub_bytes(state);
        shift_rows(state);
        if (r < 10) mds_mul(state); // MDS on all but last round
        add_round_key(state, blk->roundKeys[r]);
    }

    for (i = 0; i < 16; i++) out[i] = state[i];
}

/****************************************
 * GF(2^128) Multiplication for MAC
 *
 * We use GF(2^128) multiplication for the polynomial-based
 * MAC subkey and its operations. Similar concept to GHASH.
 ****************************************/

 /**
  * @brief R polynomial used in GF(2^128) reduction.
  */
static const uint8_t R_poly[16] = {
    0xe1,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
};

/**
 * @brief Shift a 128-bit block left by one bit.
 */
static inline void shift_left_bit(uint8_t arr[16]) {
    uint8_t carry = 0;
    for (int i = 15; i >= 0; i--) {
        uint8_t new_carry = (uint8_t)((arr[i] & 0x80) ? 1 : 0);
        arr[i] = (uint8_t)((arr[i] << 1) | carry);
        carry = new_carry;
    }
}

/**
 * @brief Shift a 128-bit block right by one bit.
 */
static inline void shift_right_bit(uint8_t arr[16]) {
    uint8_t carry = 0;
    for (int i = 0; i < 16; i++) {
        uint8_t new_carry = (uint8_t)((arr[i] & 0x01) ? 0x80 : 0);
        arr[i] = (uint8_t)((arr[i] >> 1) | carry);
        carry = new_carry;
    }
}

/**
 * @brief GF(2^128) multiplication of x by y, in place for x.
 *
 * We treat x and y as elements of GF(2^128), with a fixed polynomial reduction.
 * This is a standard bitwise multiplication followed by reduction.
 */
static inline void gf128_mul(uint8_t x[16], const uint8_t y[16]) {
    uint8_t Z[16], V[16], X_[16];
    int i, j;
    for (i = 0; i < 16; i++) { Z[i] = 0; V[i] = y[i]; X_[i] = x[i]; }

    for (i = 0; i < 128; i++) {
        if (X_[0] & 0x80) {
            for (j = 0; j < 16; j++) Z[j] ^= V[j];
        }
        {
            uint8_t lsb = (uint8_t)(V[15] & 1);
            shift_right_bit(V);
            if (lsb) {
                for (j = 0; j < 16; j++) V[j] ^= R_poly[j];
            }
        }
        shift_left_bit(X_);
    }
    for (i = 0; i < 16; i++) x[i] = Z[i];
}

/****************************************
 * Aurora Sigma AEAD
 *
 * This ties everything together:
 * - Keyed cipher and MAC subkey (H).
 * - Nonce & salt generation.
 * - Encryption with a "tweak" function per block.
 * - MAC computation over ciphertext + header.
 ****************************************/

typedef struct {
    AuroraBlock cipher;
    uint8_t H[16]; // MAC subkey derived by encrypting all-zero block
} AuroraSigma;

/**
 * @brief Constant-time comparison of two 16-byte arrays.
 * @return 1 if equal, 0 if not.
 */
static int constant_time_compare(const uint8_t a[16], const uint8_t b[16]) {
    uint8_t diff = 0;
    int i;
    for (i = 0; i < 16; i++) diff |= (uint8_t)(a[i] ^ b[i]);
    return (diff == 0);
}

/**
 * @brief Initialize random number generator (if not already).
 */
static void init_random() {
    static int seeded = 0;
    if (!seeded) {
        srand((unsigned)time(NULL));
        seeded = 1;
    }
}

/**
 * @brief Generate a random 96-bit nonce (12 bytes).
 * @param nonce Output array (12 bytes).
 */
static void generate_random_nonce(uint8_t nonce[12]) {
    init_random();
    for (int i = 0; i < 12; i++) {
        nonce[i] = (uint8_t)(rand() & 0xFF);
    }
}

/**
 * @brief Generate a random 64-bit salt.
 * @return A random 64-bit integer.
 */
static uint64_t generate_random_salt() {
    init_random();
    uint64_t s = 0;
    for (int i = 0; i < 8; i++) {
        s = (s << 8) | (uint8_t)(rand() & 0xFF);
    }
    return s;
}

/**
 * @brief Process data blocks for MAC computation.
 *
 * This takes a state S, processes the data in chunks of 16 bytes,
 * XORs each block into S, then multiplies by H in GF(2^128).
 * A final partial block (if data_len not multiple of 16) is handled.
 */
static void process_mac_blocks(uint8_t S[16], const uint8_t* data, size_t data_len, const uint8_t H[16]) {
    // domain_byte: 0xCC to separate different phases of MAC
    S[0] ^= 0xCC;
    gf128_mul(S, H);

    size_t i = 0;
    while (i + 16 <= data_len) {
        uint8_t block[16];
        for (int j = 0; j < 16; j++) block[j] = data[i + j];
        xor_block(S, block);
        gf128_mul(S, H);
        i += 16;
    }

    // Handle partial block if any remain
    if (i < data_len) {
        uint8_t block[16];
        for (int j = 0; j < 16; j++) block[j] = 0;
        {
            size_t remain = data_len - i;
            for (size_t k = 0; k < remain; k++) block[k] = data[i + k];
        }
        xor_block(S, block);
        gf128_mul(S, H);
    }
}

/**
 * @brief Compute authentication tag over ciphertext (and optionally associated data).
 *
 * In this simplified demo, we only authenticate ciphertext (no separate AAD).
 *
 * Steps:
 * 1. Process ciphertext blocks.
 * 2. XOR length block (a_bits and c_bits).
 * 3. Final domain separation.
 * 4. Encrypt the final state S to produce the tag.
 */
static void compute_tag(const AuroraBlock* cipher, const uint8_t H[16], const uint8_t* C, size_t C_len, uint8_t tag[16]) {
    uint8_t S[16];
    int i;
    for (i = 0; i < 16; i++) S[i] = 0;
    process_mac_blocks(S, C, C_len, H);

    // Length block: a_bits = 0 (no AAD), c_bits = C_len*8
    uint64_t a_bits = 0ULL;
    uint64_t c_bits = (uint64_t)C_len * 8ULL;
    uint8_t length_block[16];
    for (i = 0; i < 16; i++) length_block[i] = 0;
    store_be64(length_block, a_bits);
    store_be64(length_block + 8, c_bits);
    xor_block(S, length_block);
    gf128_mul(S, H);

    // Final domain separation: 0x42
    S[0] ^= 0x42;
    gf128_mul(S, H);

    // Encrypt final state to get tag
    uint8_t tagBlock[16];
    aurora_block_encryptBlock(cipher, S, tagBlock);
    for (i = 0; i < 16; i++) tag[i] = tagBlock[i];
}

/**
 * @brief Derive a per-block "tweak" used to produce keystream blocks.
 *
 * The tweak function uses the nonce, block counter, and salt,
 * then encrypts with Aurora to produce a tweak that is XORed into
 * the keystream generation block.
 */
static void derive_tweak(const AuroraBlock* cipher, const uint8_t nonce[12], uint32_t counter, uint64_t salt, uint8_t tweak[8]) {
    uint8_t blockIn[16], blockOut[16];
    int i;
    for (i = 0; i < 16; i++) blockIn[i] = 0;
    for (i = 0; i < 12; i++) blockIn[i] = nonce[i];
    store_be32(blockIn + 12, counter);

    // Combine salt
    {
        uint8_t saltBytes[8];
        store_be64(saltBytes, salt);
        for (i = 8; i < 16; i++) blockIn[i] ^= saltBytes[i - 8];
    }

    aurora_block_encryptBlock(cipher, blockIn, blockOut);
    for (i = 0; i < 8; i++) tweak[i] = blockOut[i];
}

/**
 * @brief Initialize AuroraSigma AEAD context with a 32-byte key.
 *
 * This sets up the cipher and computes the MAC subkey H by encrypting an all-zero block.
 */
static void aurora_sigma_init(AuroraSigma* as, const uint8_t key[32]) {
    aurora_block_init(&as->cipher, key);
    uint8_t zero[16];
    int i;
    for (i = 0; i < 16; i++) zero[i] = 0;
    aurora_block_encryptBlock(&as->cipher, zero, as->H);
}

/**
 * @brief Encrypt plaintext with AuroraSigma AEAD.
 *
 * The output format:
 *  message = nonce(12) || salt(8) || ciphertext(...) || tag(16)
 *
 * @param as Pointer to AuroraSigma context (initialized with aurora_sigma_init).
 * @param key 32-byte key (not re-used here, kept for interface symmetry).
 * @param plaintext Input plaintext buffer.
 * @param plaintext_len Length of plaintext.
 * @param message Output buffer: must be at least plaintext_len+36 bytes.
 * @param message_len Output length of the encrypted message.
 * @return 1 on success, 0 on failure.
 */
static int aurora_sigma_encrypt(
    AuroraSigma* as,
    const uint8_t key[32],
    const uint8_t* plaintext, size_t plaintext_len,
    uint8_t* message, size_t* message_len
) {
    (void)key; // Key already used in as->cipher during init.
    uint8_t nonce[12];
    generate_random_nonce(nonce);
    uint64_t salt = generate_random_salt();

    // Format:
    // message = nonce(12) || salt(8) || ciphertext(plaintext_len bytes) || tag(16)

    uint8_t saltBytes[8];
    store_be64(saltBytes, salt);

    // Set nonce and salt in output
    {
        int i;
        for (i = 0; i < 12; i++) message[i] = nonce[i];
        for (i = 0; i < 8; i++) message[12 + i] = saltBytes[i];
    }

    // Encrypt plaintext to ciphertext using a per-block derived keystream
    size_t i;
    for (i = 0; i < plaintext_len; i += 16) {
        uint8_t keystream[16], tweak[8], inBlock[16];
        int j;
        for (j = 0; j < 16; j++) keystream[j] = 0;
        for (j = 0; j < 8; j++) tweak[j] = 0;
        for (j = 0; j < 16; j++) inBlock[j] = 0;

        uint32_t blkCount = (uint32_t)(i / 16);
        derive_tweak(&as->cipher, nonce, blkCount, salt, tweak);

        // The "inBlock" is a form of nonce||block_count with tweak XORed
        for (j = 0; j < 12; j++) inBlock[j] = nonce[j];
        store_be32(inBlock + 12, blkCount);
        for (j = 0; j < 8; j++) inBlock[j] ^= tweak[j];

        aurora_block_encryptBlock(&as->cipher, inBlock, keystream);

        size_t remain = plaintext_len - i;
        if (remain > 16) remain = 16;
        for (j = 0; j < (int)remain; j++) {
            message[20 + i + j] = (uint8_t)(plaintext[i + j] ^ keystream[j]);
        }
    }

    // Compute authentication tag over (nonce||salt||ciphertext)
    {
        size_t full_data_len = 12 + 8 + plaintext_len;
        uint8_t tag[16];
        compute_tag(&as->cipher, as->H, message, full_data_len, tag);

        // Append tag after ciphertext
        size_t offset = 20 + plaintext_len;
        for (int j = 0; j < 16; j++) message[offset + j] = tag[j];
    }

    *message_len = 12 + 8 + plaintext_len + 16; // total length
    return 1;
}

/**
 * @brief Decrypt message with AuroraSigma AEAD.
 *
 * Input format:
 *  message = nonce(12) || salt(8) || ciphertext(...) || tag(16)
 *
 * @param as AuroraSigma context (already init).
 * @param key 32-byte key (not used again, here for interface).
 * @param message Input message.
 * @param message_len length of message.
 * @param plaintext Output buffer, must be large enough for message_len-36.
 * @param plaintext_len Output plaintext length.
 * @return 1 if tag is correct and decryption succeeded, 0 otherwise.
 */
static int aurora_sigma_decrypt(
    AuroraSigma* as,
    const uint8_t key[32],
    const uint8_t* message, size_t message_len,
    uint8_t* plaintext, size_t* plaintext_len
) {
    (void)key; // Already used during init in as.

    // Must have at least nonce(12)+salt(8)+tag(16) = 36 bytes + ciphertext
    if (message_len < 36) return 0;
    size_t ct_len = message_len - 12 - 8 - 16;

    // Extract nonce
    uint8_t nonce[12];
    {
        int i;
        for (i = 0; i < 12; i++) nonce[i] = message[i];
    }

    // Extract salt
    uint64_t salt = 0;
    {
        int i;
        for (i = 0; i < 8; i++) {
            salt = (salt << 8) | message[12 + i];
        }
    }

    const uint8_t* ciphertext = message + 20;
    const uint8_t* tag = message + 20 + ct_len;

    // Verify tag
    {
        size_t full_data_len = 12 + 8 + ct_len;
        uint8_t calcTag[16];
        compute_tag(&as->cipher, as->H, message, full_data_len, calcTag);
        if (!constant_time_compare(tag, calcTag)) {
            // Tag mismatch means tampering or invalid key.
            return 0;
        }
    }

    // Tag correct, proceed to decrypt ciphertext
    *plaintext_len = ct_len;
    {
        size_t i;
        for (i = 0; i < ct_len; i += 16) {
            uint8_t keystream[16], tweak[8], inBlock[16];
            int j;
            for (j = 0; j < 16; j++) keystream[j] = 0;
            for (j = 0; j < 8; j++) tweak[j] = 0;
            for (j = 0; j < 16; j++) inBlock[j] = 0;

            uint32_t blkCount = (uint32_t)(i / 16);
            derive_tweak(&as->cipher, nonce, blkCount, salt, tweak);

            for (j = 0; j < 12; j++) inBlock[j] = nonce[j];
            store_be32(inBlock + 12, blkCount);
            for (j = 0; j < 8; j++) inBlock[j] ^= tweak[j];

            aurora_block_encryptBlock(&as->cipher, inBlock, keystream);

            size_t remain = ct_len - i;
            if (remain > 16) remain = 16;
            for (j = 0; j < (int)remain; j++) {
                plaintext[i + j] = (uint8_t)(ciphertext[i + j] ^ keystream[j]);
            }
        }
    }

    return 1;
}
