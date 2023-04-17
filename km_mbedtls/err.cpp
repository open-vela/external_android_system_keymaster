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

#include <hardware/keymaster_defs.h>
#include <keymaster/logger.h>
#include <openssl/err.h>
#include <mbedtls/error.h>
#include <mbedtls/cipher.h>
#include <errno.h>

unsigned long ERR_peek_last_error()
{
    return errno;
}

void ERR_error_string_n(unsigned long e, char* buf, size_t len) {
    mbedtls_strerror(e, buf, len);
}

namespace keymaster {

keymaster_error_t TranslateLastOpenSslError(bool log_message)
{
    int reason = errno;
    if (log_message) {
        char buf[128];
        mbedtls_strerror(reason, buf, sizeof(buf));
        LOG_E("mbedtls error:%s", buf);
    }

    /* Handle global error reasons */
    switch (reason) {
    case MBEDTLS_ERR_CIPHER_ALLOC_FAILED:
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;

    case MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA:
    case MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE:
        return KM_ERROR_UNSUPPORTED_ALGORITHM;

    case MBEDTLS_ERR_CIPHER_INVALID_PADDING:
        return KM_ERROR_UNSUPPORTED_PADDING_MODE;
    case MBEDTLS_ERR_CIPHER_FULL_BLOCK_EXPECTED:
        return KM_ERROR_INCOMPATIBLE_BLOCK_MODE;
    case MBEDTLS_ERR_CIPHER_AUTH_FAILED:
        return KM_ERROR_INVALID_USER_ID;

    case MBEDTLS_ERR_CIPHER_INVALID_CONTEXT:
    case MBEDTLS_CIPHER_VARIABLE_IV_LEN:
    case MBEDTLS_CIPHER_VARIABLE_KEY_LEN:
        return KM_ERROR_UNKNOWN_ERROR;
    default:
        break;
    }

    LOG_E("mbedtls error %d", reason);
    return KM_ERROR_UNKNOWN_ERROR;
}
} // namespace keymaster
