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

#include <mbedtls/md.h>
#include <openssl/digest.h>
#include <stdlib.h>

EVP_MD_CTX* EVP_MD_CTX_new(void) {
    mbedtls_md_context_t* ctx =
        static_cast<mbedtls_md_context_t*>(malloc(sizeof(mbedtls_md_context_t)));
    EVP_MD_CTX_init(reinterpret_cast<EVP_MD_CTX*>(ctx));
    return reinterpret_cast<EVP_MD_CTX*>(ctx);
}

void EVP_MD_CTX_free(EVP_MD_CTX* ctx) {
    if (ctx != nullptr) {
        EVP_MD_CTX_cleanup(ctx);
        free(ctx);
    }
}

const EVP_MD* EVP_md5(void) {
    return nullptr;
}

int EVP_DigestInit_ex(EVP_MD_CTX* ctx, const EVP_MD* type, ENGINE* engine) {
    mbedtls_md_context_t* m_ctx = reinterpret_cast<mbedtls_md_context_t*>(ctx);
    if (mbedtls_md_setup(m_ctx, reinterpret_cast<const mbedtls_md_info_t*>(type), 0) != 0) {
        return 0;
    }
    if (mbedtls_md_starts(m_ctx) != 0) {
        return 0;
    }
    return 1;
}

int EVP_DigestUpdate(EVP_MD_CTX* ctx, const void* data, size_t len) {
    if (mbedtls_md_update(reinterpret_cast<mbedtls_md_context_t*>(ctx),
                          static_cast<const unsigned char*>(data), len) != 0) {
        return 0;
    }
    return 1;
}

int EVP_DigestFinal_ex(EVP_MD_CTX* ctx, uint8_t* md_out, unsigned int* size) {
    const mbedtls_md_info_t* md_info = reinterpret_cast<mbedtls_md_context_t*>(ctx)->md_info;
    if (md_info == nullptr) {
        return 0;
    }
    *size = mbedtls_md_get_size(md_info);
    if (mbedtls_md_finish(reinterpret_cast<mbedtls_md_context_t*>(ctx), md_out) != 0) {
        return 0;
    }
    return 1;
}

int EVP_MD_CTX_cleanup(EVP_MD_CTX* ctx) {
    mbedtls_md_free(reinterpret_cast<mbedtls_md_context_t*>(ctx));
}
