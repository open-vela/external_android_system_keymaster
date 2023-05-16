/*
 * Copyright (C) 2023 Xiaomi Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef KEYMASTER_OPENSSL_CIPER_H
#define KEYMASTER_OPENSSL_CIPER_H

#include <openssl/base.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CIPHER_R_BAD_DECRYPT 101
#define EVP_CTRL_GCM_GET_TAG 0x10
#define EVP_CTRL_GCM_SET_TAG 0x11

void EVP_CIPHER_CTX_init(EVP_CIPHER_CTX* ctx);
int EVP_CIPHER_CTX_cleanup(EVP_CIPHER_CTX* ctx);

const EVP_CIPHER* EVP_aes_128_ecb(void);
const EVP_CIPHER* EVP_aes_192_ecb(void);
const EVP_CIPHER* EVP_aes_256_ecb(void);
const EVP_CIPHER* EVP_aes_128_cbc(void);
const EVP_CIPHER* EVP_aes_192_cbc(void);
const EVP_CIPHER* EVP_aes_256_cbc(void);
const EVP_CIPHER* EVP_aes_128_ctr(void);
const EVP_CIPHER* EVP_aes_192_ctr(void);
const EVP_CIPHER* EVP_aes_256_ctr(void);
const EVP_CIPHER* EVP_aes_128_gcm(void);
const EVP_CIPHER* EVP_aes_192_gcm(void);
const EVP_CIPHER* EVP_aes_256_gcm(void);

const EVP_CIPHER* EVP_des_ede(void);
const EVP_CIPHER* EVP_des_ede3(void);
const EVP_CIPHER* EVP_des_ede_cbc(void);
const EVP_CIPHER* EVP_des_ede3_cbc(void);

int EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX* ctx, int type, int arg, void* ptr);
int EVP_CIPHER_CTX_set_padding(EVP_CIPHER_CTX* c, int pad);
int EVP_CipherInit_ex(EVP_CIPHER_CTX* ctx, const EVP_CIPHER* cipher, ENGINE* impl,
                      const unsigned char* key, const unsigned char* iv, int enc);
int EVP_CipherUpdate(EVP_CIPHER_CTX* ctx, unsigned char* out, int* outl, const unsigned char* in,
                     int inl);
int EVP_CipherFinal_ex(EVP_CIPHER_CTX* ctx, unsigned char* outm, int* outl);

int EVP_MD_CTX_cleanup(EVP_MD_CTX* ctx);

EVP_CIPHER_CTX* EVP_CIPHER_CTX_new(void);

void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX* ctx);

int EVP_EncryptInit_ex(EVP_CIPHER_CTX* ctx, const EVP_CIPHER* cipher, ENGINE* impl,
                       const uint8_t* key, const uint8_t* iv);

int EVP_DecryptInit_ex(EVP_CIPHER_CTX* ctx, const EVP_CIPHER* cipher, ENGINE* impl,
                       const uint8_t* key, const uint8_t* iv);

int EVP_EncryptUpdate(EVP_CIPHER_CTX* ctx, uint8_t* out, int* out_len, const uint8_t* in,
                      int in_len);

int EVP_EncryptFinal_ex(EVP_CIPHER_CTX* ctx, uint8_t* out, int* out_len);

int EVP_DecryptUpdate(EVP_CIPHER_CTX* ctx, uint8_t* out, int* out_len, const uint8_t* in,
                      int in_len);

int EVP_DecryptFinal_ex(EVP_CIPHER_CTX* ctx, uint8_t* out, int* out_len);

#ifdef __cplusplus
}

#if !defined(BORINGSSL_NO_CXX)
extern "C++" {

BSSL_NAMESPACE_BEGIN

BORINGSSL_MAKE_DELETER(EVP_CIPHER_CTX, EVP_CIPHER_CTX_free)

using ScopedEVP_CIPHER_CTX =
    internal::StackAllocated<EVP_CIPHER_CTX, int, EVP_CIPHER_CTX_init,
                             EVP_CIPHER_CTX_cleanup>;

BSSL_NAMESPACE_END

}  // extern C++

#endif

#endif

#endif  // KEYMASTER_OPENSSL_CIPER_H