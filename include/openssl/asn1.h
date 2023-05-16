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

#ifndef KEYMASTER_OPENSSL_ASN1_H
#define KEYMASTER_OPENSSL_ASN1_H

#include <openssl/base.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MBSTRING_FLAG 0x1000
#define MBSTRING_UTF8 (MBSTRING_FLAG)
#define MBSTRING_ASC (MBSTRING_FLAG | 1)

#define V_ASN1_NULL 5

void ASN1_BIT_STRING_free(ASN1_BIT_STRING* a);

void ASN1_INTEGER_free(ASN1_INTEGER* a);

void ASN1_OBJECT_free(ASN1_OBJECT* a);

void ASN1_OCTET_STRING_free(ASN1_OCTET_STRING* a);

void ASN1_TIME_free(ASN1_TIME* a);

ASN1_BIT_STRING* ASN1_BIT_STRING_new(void);

int ASN1_BIT_STRING_set_bit(ASN1_BIT_STRING* str, int n, int value);

ASN1_OCTET_STRING* ASN1_OCTET_STRING_new(void);

int i2d_ASN1_BIT_STRING(const ASN1_BIT_STRING* in, uint8_t** outp);

int ASN1_OCTET_STRING_set(ASN1_OCTET_STRING* str, const unsigned char* data, int len);

ASN1_INTEGER* ASN1_INTEGER_new(void);

ASN1_INTEGER* BN_to_ASN1_INTEGER(const BIGNUM* bn, ASN1_INTEGER* ai);

ASN1_TIME* ASN1_TIME_new(void);

ASN1_TIME* ASN1_TIME_set(ASN1_TIME* s, time_t t);

#ifdef __cplusplus
}
#endif

#endif  // KEYMASTER_OPENSSL_ASN1_H