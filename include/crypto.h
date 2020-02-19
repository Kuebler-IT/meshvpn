/*
 * MeshVPN - A open source peer-to-peer VPN (forked from PeerVPN)
 *
 * Copyright (C) 2012-2016  Tobias Volk <mail@tobiasvolk.de>
 * Copyright (C) 2016       Hideman Developer <company@hideman.net>
 * Copyright (C) 2017       Benjamin Kübler <b.kuebler@kuebler-it.de>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef H_CRYPTO
#define H_CRYPTO

#include "util.h"
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>


// supported crypto algorithms
#define crypto_AES256 1


// supported hmac algorithms
#define crypto_SHA256 1

// maximum iv & hmac size
#define crypto_MAXIVSIZE EVP_MAX_IV_LENGTH
#define crypto_MAXHMACSIZE EVP_MAX_MD_SIZE


// cipher context storage
struct s_crypto {
        EVP_CIPHER_CTX *enc_ctx;
        EVP_CIPHER_CTX *dec_ctx;
        HMAC_CTX *hmac_ctx;
};


// cipher pointer storage
struct s_crypto_cipher {
        const EVP_CIPHER *cipher;
};

// md pointer storage
struct s_crypto_md {
        const EVP_MD *md;
};

// return EVP cipher key size
int cryptoGetEVPCipherSize(struct s_crypto_cipher *st_cipher);

// return EVP cipher
struct s_crypto_cipher cryptoGetEVPCipher(const EVP_CIPHER *cipher);

// return EVP md
struct s_crypto_md cryptoGetEVPMD(const EVP_MD *md);

int cryptoRandInit();

// generate random bytes
int cryptoRand(unsigned char *buf, const int buf_size);

// generate random int64 number
int64_t cryptoRand64();

// generate random int number
int cryptoRandInt();

// generate keys
int cryptoSetKeys(struct s_crypto *ctxs, const int count, const unsigned char *secret_buf, const int secret_len, const unsigned char *nonce_buf, const int nonce_len);

// generate random keys
int cryptoSetKeysRandom(struct s_crypto *ctxs, const int count);

// destroy cipher contexts
void cryptoDestroy(struct s_crypto *ctxs, const int count);

// create cipher contexts
int cryptoCreate(struct s_crypto *ctxs, const int count);

// generate HMAC tag
int cryptoHMAC(struct s_crypto *ctx, unsigned char *hmac_buf, const int hmac_len, const unsigned char *in_buf, const int in_len);

// generate session keys
int cryptoSetSessionKeys(struct s_crypto *session_ctx, struct s_crypto *cipher_keygen_ctx, struct s_crypto *md_keygen_ctx, const unsigned char *nonce, const int nonce_len, const int cipher_algorithm, const int hmac_algorithm);

// encrypt buffer
int cryptoEnc(struct s_crypto *ctx, unsigned char *enc_buf, const int enc_len, const unsigned char *dec_buf, const int dec_len, const int hmac_len, const int iv_len);

// decrypt buffer
int cryptoDec(struct s_crypto *ctx, unsigned char *dec_buf, const int dec_len, const unsigned char *enc_buf, const int enc_len, const int hmac_len, const int iv_len);

// calculate hash
int cryptoCalculateHash(unsigned char *hash_buf, const int hash_len, const unsigned char *in_buf, const int in_len, const EVP_MD *hash_func);

// calculate SHA-256 hash
int cryptoCalculateSHA256(unsigned char *hash_buf, const int hash_len, const unsigned char *in_buf, const int in_len);

// calculate SHA-512 hash
int cryptoCalculateSHA512(unsigned char *hash_buf, const int hash_len, const unsigned char *in_buf, const int in_len);

// generate session keys from password
int cryptoSetSessionKeysFromPassword(struct s_crypto *session_ctx, const unsigned char *password, const int password_len, const int cipher_algorithm, const int hmac_algorithm);

#if OPENSSL_VERSION_NUMBER < 0x10100000L
void DH_get0_key(const DH *dh, const BIGNUM **pub_key, const BIGNUM **priv_key);
HMAC_CTX *HMAC_CTX_new(void);
void HMAC_CTX_free(HMAC_CTX *ctx);
EVP_CIPHER_CTX *EVP_CIPHER_CTX_new(void);
void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *ctx);
#endif

#endif
