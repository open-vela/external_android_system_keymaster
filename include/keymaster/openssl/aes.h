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

#ifndef KEYMASTER_OPENSSL_AES_H
#define KEYMASTER_OPENSSL_AES_H

#include <openssl/base.h>

#ifdef __cplusplus
extern "C" {
#endif

#define AES_ENCRYPT 1
#define AES_DECRYPT 0

#define AES_BLOCK_SIZE 16
#define AES_MAXNR 14

struct aes_key_st {
    uint32_t rd_key[4 * (AES_MAXNR + 1)];
    unsigned rounds;
};

typedef struct aes_key_st AES_KEY;

int AES_set_encrypt_key(const uint8_t* key, unsigned bits, AES_KEY* aeskey);

void AES_encrypt(const uint8_t* in, uint8_t* out, const AES_KEY* key);

int AES_set_decrypt_key(const uint8_t* key, unsigned bits, AES_KEY* aeskey);

void AES_decrypt(const uint8_t* in, uint8_t* out, const AES_KEY* key);

#ifdef __cplusplus
}
#endif

#endif  // KEYMASTER_OPENSSL_AES_H