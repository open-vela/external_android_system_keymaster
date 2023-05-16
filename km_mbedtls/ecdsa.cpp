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

#include <openssl/ecdsa.h>

size_t ECDSA_size(const EC_KEY* key) {
    return 0;
}

int ECDSA_sign(int type, const uint8_t* digest, size_t digest_len, uint8_t* sig,
               unsigned int* sig_len, const EC_KEY* key) {
    return 0;
}

int ECDSA_verify(int type, const uint8_t* digest, size_t digest_len, const uint8_t* sig,
                 size_t sig_len, const EC_KEY* key) {
    return 0;
}