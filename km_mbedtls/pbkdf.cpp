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

#include <errno.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <mbedtls/pkcs5.h>

// derives a key from a password using a salt and iteration count as specified in RFC 2898
int PKCS5_PBKDF2_HMAC(const char* password, size_t password_len, const uint8_t* salt,
                      size_t salt_len, unsigned iterations, const EVP_MD* digest, size_t key_len,
                      uint8_t* out_key) {
    mbedtls_md_context_t md_ctx;
    mbedtls_md_init(&md_ctx);
    int generate_result = 0;
    int ret = 0;
    ret = mbedtls_md_setup(&md_ctx, reinterpret_cast<const mbedtls_md_info_t*>(digest), 1);
    if (ret == 0 && mbedtls_pkcs5_pbkdf2_hmac(
                        &md_ctx, reinterpret_cast<const unsigned char*>(password), password_len,
                        salt, salt_len, iterations, key_len, out_key) == 0) {
        generate_result = 1;
    }

    mbedtls_md_free(&md_ctx);
    return generate_result;
}