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

#ifndef KEYMASTER_OPENSSL_BN_H
#define KEYMASTER_OPENSSL_BN_H

#include <openssl/asn1.h>
#include <openssl/base.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BN_ULONG uint32_t
#define BN_BITS2 32

BN_CTX* BN_CTX_new(void);
void BN_CTX_free(BN_CTX* a);
void BN_free(BIGNUM* a);

typedef uint32_t BN_ULONG;

BN_ULONG BN_get_word(const BIGNUM* bn);

unsigned BN_num_bits(const BIGNUM* bn);

BIGNUM* BN_new(void);

int BN_bn2binpad(const BIGNUM* in, uint8_t* out, int len);

int BN_set_word(BIGNUM* bn, BN_ULONG value);

BIGNUM* BN_dup(const BIGNUM* src);

BIGNUM* BN_bin2bn(const uint8_t* in, size_t len, BIGNUM* ret);

int BN_one(BIGNUM* bn);

#ifdef __cplusplus
}
#endif

#if !defined(BORINGSSL_NO_CXX)
extern "C++" {

BSSL_NAMESPACE_BEGIN

BORINGSSL_MAKE_DELETER(BIGNUM, BN_free)

BSSL_NAMESPACE_END

} // extern C++

#endif

#endif // KEYMASTER_OPENSSL_BN_H