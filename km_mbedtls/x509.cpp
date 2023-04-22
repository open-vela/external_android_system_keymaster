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

#include <openssl/x509.h>

void X509_free(X509* a) {}

void X509_EXTENSION_free(X509_EXTENSION* a) {}

int X509_set_notAfter(X509* x509, const ASN1_TIME* tm) {
    return 0;
}

void X509_NAME_free(X509_NAME* a) {}

void X509_ALGOR_free(X509_ALGOR* a) {}

int X509_sign(X509* x509, EVP_PKEY* pkey, const EVP_MD* md) {
    return 0;
}

int X509_add_ext(X509* x, const X509_EXTENSION* ex, int loc) {
    return 0;
}

int X509_set_pubkey(X509* x509, EVP_PKEY* pkey) {
    return 0;
}

X509_EXTENSION* X509_EXTENSION_create_by_NID(X509_EXTENSION** ex, int nid, int crit,
                                             const ASN1_OCTET_STRING* data) {
    return nullptr;
}

X509* X509_new(void) {
    return nullptr;
}

int X509_set_version(X509* x509, long version) {
    return 0;
}

int X509_set_serialNumber(X509* x509, const ASN1_INTEGER* serial) {
    return 0;
}

int X509_set_subject_name(X509* x509, X509_NAME* name) {
    return 0;
}

int X509_set_issuer_name(X509* x509, X509_NAME* name) {
    return 0;
}

int X509_set_notBefore(X509* x509, const ASN1_TIME* tm) {
    return 0;
}

int X509_ALGOR_set0(X509_ALGOR* alg, ASN1_OBJECT* obj, int param_type, void* param_value) {
    return 0;
}

int X509_set1_signature_algo(X509* x509, const X509_ALGOR* algo) {
    return 0;
}

int X509_set1_signature_value(X509* x509, const uint8_t* sig, size_t sig_len) {
    return 0;
}

X509_NAME* X509_NAME_new(void) {
    return nullptr;
}

int X509_NAME_add_entry_by_txt(X509_NAME* name, const char* field, int type, const uint8_t* bytes,
                               int len, int loc, int set) {
    return 0;
}

X509_NAME* d2i_X509_NAME(X509_NAME** out, const uint8_t** inp, long len) {
    return nullptr;
}

X509_ALGOR* X509_ALGOR_new(void) {
    return nullptr;
}

int i2d_X509(X509* x509, uint8_t** outp) {
    return 0;
}

PKCS8_PRIV_KEY_INFO* d2i_PKCS8_PRIV_KEY_INFO(PKCS8_PRIV_KEY_INFO* info, const uint8_t** key_data,
                                             size_t key_length) {
    return nullptr;
}

void PKCS8_PRIV_KEY_INFO_free(PKCS8_PRIV_KEY_INFO* key) {}

EVP_PKEY* EVP_PKCS82PKEY(const PKCS8_PRIV_KEY_INFO* p8) {
    return nullptr;
}