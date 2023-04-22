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

#ifndef KEYMASTER_OPENSSL_CURVE25519_H
#define KEYMASTER_OPENSSL_CURVE25519_H

#include <openssl/base.h>

#ifdef __cplusplus
extern "C" {
#endif

#define X25519_PRIVATE_KEY_LEN 32
#define X25519_PUBLIC_VALUE_LEN 32
#define X25519_SHARED_KEY_LEN 32
#define ED25519_PRIVATE_KEY_LEN 64
#define ED25519_PUBLIC_KEY_LEN 32
#define ED25519_SIGNATURE_LEN 64

// ED25519_keypair sets |out_public_key| and |out_private_key| to a freshly
// generated, public–private key pair.
void ED25519_keypair(uint8_t out_public_key[32], uint8_t out_private_key[64]);

void X25519_keypair(uint8_t out_public_value[32], uint8_t out_private_key[32]);

int X25519(uint8_t out_shared_key[32], const uint8_t private_key[32],
           const uint8_t peer_public_value[32]);

#ifdef __cplusplus
}
#endif
#endif  // KEYMASTER_OPENSSL_CURVE25519_H