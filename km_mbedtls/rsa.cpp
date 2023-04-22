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

#include <mbedtls/rsa.h>
#include <openssl/err.h>
#include <openssl/rsa.h>

unsigned RSA_size(const RSA* rsa) {
    size_t rsa_size =
        (mbedtls_rsa_get_len(reinterpret_cast<const mbedtls_rsa_context*>(rsa)) + 7) / 8;
    return rsa_size;
}

const BIGNUM* RSA_get0_e(const RSA* rsa) {
    return nullptr;
}

RSA* RSA_new(void) {
    return nullptr;
}

void RSA_free(RSA* rsa) {}

int RSA_generate_key_ex(RSA* rsa, int bits, const BIGNUM* e_value, BN_GENCB* cb) {
    return 0;
}

int RSA_private_encrypt(size_t flen, const uint8_t* from, uint8_t* to, RSA* rsa, int padding) {
    return 0;
}

int RSA_public_decrypt(size_t flen, const uint8_t* from, uint8_t* to, RSA* rsa, int padding) {
    return 0;
}