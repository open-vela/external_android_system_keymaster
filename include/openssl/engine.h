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

#ifndef KEYMASTER_OPENSSL_ENGINE_H
#define KEYMASTER_OPENSSL_ENGINE_H

#include <openssl/base.h>

#ifdef __cplusplus
extern "C" {
#endif

struct openssl_method_common_st {
    int references;  // dummy – not used.
    char is_static;
};

ENGINE* ENGINE_new(void);

void ENGINE_free(ENGINE* a);

int ENGINE_set_RSA_method(ENGINE* engine, const RSA_METHOD* method, size_t method_size);

int ENGINE_set_ECDSA_method(ENGINE* engine, const ECDSA_METHOD* method, size_t method_size);

#ifdef __cplusplus
}
#endif

#endif  // KEYMASTER_OPENSSL_ENGINE_H