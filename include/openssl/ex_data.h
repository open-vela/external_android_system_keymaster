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

#ifndef KEYMASTER_OPENSSL_EX_DATA_H
#define KEYMASTER_OPENSSL_EX_DATA_H

#include <openssl/base.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef int CRYPTO_EX_unused;
typedef struct CRYPTO_EX_DATA CRYPTO_EX_DATA;

typedef int CRYPTO_EX_dup(CRYPTO_EX_DATA* to, const CRYPTO_EX_DATA* from, void** from_d, int index,
                          long argl, void* argp);

typedef void CRYPTO_EX_free(void* parent, void* ptr, CRYPTO_EX_DATA* ad, int index, long argl,
                            void* argp);

#ifdef __cplusplus
}
#endif
#endif  // KEYMASTER_OPENSSL_EX_DATA_H