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

#ifndef KEYMASTER_OPENSSL_BASE_H
#define KEYMASTER_OPENSSL_BASE_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ASN1_BIT_STRING ASN1_STRING

typedef struct EVP_CIPHER EVP_CIPHER;
typedef struct EVP_CIPHER_CTX EVP_CIPHER_CTX;
typedef struct ENGINE ENGINE;
typedef struct EVP_MD EVP_MD;
typedef struct EVP_MD_CTX EVP_MD_CTX;
typedef struct ASN1_BIT_STRING ASN1_BIT_STRING;
typedef struct ASN1_INTEGER ASN1_INTEGER;
typedef struct ASN1_OBJECT ASN1_OBJECT;
typedef struct ASN1_OCTET_STRING ASN1_OCTET_STRING;
typedef struct ASN1_TIME ASN1_TIME;
typedef struct BN_CTX BN_CTX;
typedef struct EC_GROUP EC_GROUP;
typedef struct EC_KEY EC_KEY;
typedef struct EC_POINT EC_POINT;
typedef struct EVP_PKEY EVP_PKEY;
typedef struct EVP_PKEY_CTX EVP_PKEY_CTX;
typedef struct PKCS8_PRIV_KEY_INFO PKCS8_PRIV_KEY_INFO;
typedef struct RSA RSA;
typedef struct X509 X509;
typedef struct X509_ALGOR X509_ALGOR;
typedef struct X509_EXTENSION X509_EXTENSION;
typedef struct X509_NAME X509_NAME;
typedef struct BIGNUM BIGNUM;
typedef struct HMAC_CTX HMAC_CTX;
typedef struct SHA_CTX SHA_CTX;
typedef struct rsa_meth_st RSA_METHOD;
typedef struct ecdsa_method_st ECDSA_METHOD;
typedef struct BN_GENCB BN_GENCB;
typedef struct sha256_state_st SHA256_CTX;
typedef struct cbb_st CBB;
typedef struct ecdsa_sig_st ECDSA_SIG;

#ifdef __cplusplus
}
#endif

#endif  // KEYMASTER_OPENSSL_BASE_H