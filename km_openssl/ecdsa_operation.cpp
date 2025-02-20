/*
 * Copyright 2014 The Android Open Source Project
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

#include <keymaster/km_openssl/ecdsa_operation.h>

#include <openssl/curve25519.h>
#include <openssl/ecdsa.h>

#include <keymaster/km_openssl/ec_key.h>
#include <keymaster/km_openssl/openssl_err.h>
#include <keymaster/km_openssl/openssl_utils.h>

namespace keymaster {

// Message size limit for Ed25519 messages, which are not pre-digested.
static const size_t MAX_ED25519_MSG_SIZE = 16 * 1024;

static const keymaster_digest_t supported_digests[] = {KM_DIGEST_NONE,      KM_DIGEST_SHA1,
                                                       KM_DIGEST_SHA_2_224, KM_DIGEST_SHA_2_256,
                                                       KM_DIGEST_SHA_2_384, KM_DIGEST_SHA_2_512};

OperationPtr EcdsaOperationFactory::CreateOperation(Key&& key, const AuthorizationSet& begin_params,
                                                    keymaster_error_t* error) {
    const AsymmetricKey& ecdsa_key = static_cast<AsymmetricKey&>(key);

    EVP_PKEY_Ptr pkey(ecdsa_key.InternalToEvp());
    if (pkey.get() == nullptr) {
        *error = KM_ERROR_UNKNOWN_ERROR;
        return nullptr;
    }

    keymaster_digest_t digest;
    if (!GetAndValidateDigest(begin_params, ecdsa_key, &digest, error, true)) {
        return nullptr;
    }

    *error = KM_ERROR_OK;
    auto op = OperationPtr(InstantiateOperation(key.hw_enforced_move(), key.sw_enforced_move(),
                                                digest, pkey.release()));
    if (!op) *error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
    return op;
}

const keymaster_digest_t* EcdsaOperationFactory::SupportedDigests(size_t* digest_count) const {
    *digest_count = array_length(supported_digests);
    return supported_digests;
}

EcdsaOperation::~EcdsaOperation() {
    if (ecdsa_key_ != nullptr) EVP_PKEY_free(ecdsa_key_);
    EVP_MD_CTX_free(digest_ctx_);
}

keymaster_error_t EcdsaOperation::InitDigest() {
    switch (digest_) {
    case KM_DIGEST_NONE:
        return KM_ERROR_OK;
    case KM_DIGEST_MD5:
        return KM_ERROR_UNSUPPORTED_DIGEST;
    case KM_DIGEST_SHA1:
        digest_algorithm_ = EVP_sha1();
        return KM_ERROR_OK;
    case KM_DIGEST_SHA_2_224:
        digest_algorithm_ = EVP_sha224();
        return KM_ERROR_OK;
    case KM_DIGEST_SHA_2_256:
        digest_algorithm_ = EVP_sha256();
        return KM_ERROR_OK;
    case KM_DIGEST_SHA_2_384:
        digest_algorithm_ = EVP_sha384();
        return KM_ERROR_OK;
    case KM_DIGEST_SHA_2_512:
        digest_algorithm_ = EVP_sha512();
        return KM_ERROR_OK;
    default:
        return KM_ERROR_UNSUPPORTED_DIGEST;
    }
}

inline size_t min(size_t a, size_t b) {
    return (a < b) ? a : b;
}

keymaster_error_t EcdsaOperation::StoreData(const Buffer& input, size_t* input_consumed) {
    if (!data_.reserve((EVP_PKEY_bits(ecdsa_key_) + 7) / 8))
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;

    if (!data_.write(input.peek_read(), min(data_.available_write(), input.available_read())))
        return KM_ERROR_UNKNOWN_ERROR;

    *input_consumed = input.available_read();
    return KM_ERROR_OK;
}

keymaster_error_t EcdsaSignOperation::Begin(const AuthorizationSet& /* input_params */,
                                            AuthorizationSet* /* output_params */) {
    auto rc = GenerateRandom(reinterpret_cast<uint8_t*>(&operation_handle_),
                             (size_t)sizeof(operation_handle_));
    if (rc != KM_ERROR_OK) return rc;

    keymaster_error_t error = InitDigest();
    if (error != KM_ERROR_OK) return error;

    if (digest_ == KM_DIGEST_NONE) return KM_ERROR_OK;

    EVP_PKEY_CTX* pkey_ctx;
    if (EVP_DigestSignInit(digest_ctx_, &pkey_ctx, digest_algorithm_, nullptr /* engine */,
                           ecdsa_key_) != 1)
        return TranslateLastOpenSslError();
    return KM_ERROR_OK;
}

keymaster_error_t EcdsaSignOperation::Update(const AuthorizationSet& /* additional_params */,
                                             const Buffer& input,
                                             AuthorizationSet* /* output_params */,
                                             Buffer* /* output */, size_t* input_consumed) {
    if (digest_ == KM_DIGEST_NONE) return StoreData(input, input_consumed);

    if (EVP_DigestSignUpdate(digest_ctx_, input.peek_read(), input.available_read()) != 1)
        return TranslateLastOpenSslError();
    *input_consumed = input.available_read();
    return KM_ERROR_OK;
}

keymaster_error_t EcdsaSignOperation::Finish(const AuthorizationSet& additional_params,
                                             const Buffer& input, const Buffer& /* signature */,
                                             AuthorizationSet* /* output_params */,
                                             Buffer* output) {
    if (!output) return KM_ERROR_OUTPUT_PARAMETER_NULL;

    keymaster_error_t error = UpdateForFinish(additional_params, input);
    if (error != KM_ERROR_OK) return error;

    size_t siglen;
    if (digest_ == KM_DIGEST_NONE) {
        UniquePtr<EC_KEY, EC_KEY_Delete> ecdsa(EVP_PKEY_get1_EC_KEY(ecdsa_key_));
        if (!ecdsa.get()) return TranslateLastOpenSslError();

        output->Reinitialize(ECDSA_size(ecdsa.get()));
        unsigned int siglen_tmp;
        if (!ECDSA_sign(0 /* type -- ignored */, data_.peek_read(), data_.available_read(),
                        output->peek_write(), &siglen_tmp, ecdsa.get()))
            return TranslateLastOpenSslError();
        siglen = siglen_tmp;
    } else {
        if (EVP_DigestSignFinal(digest_ctx_, nullptr /* signature */, &siglen) != 1)
            return TranslateLastOpenSslError();
        if (!output->Reinitialize(siglen)) return KM_ERROR_MEMORY_ALLOCATION_FAILED;
        if (EVP_DigestSignFinal(digest_ctx_, output->peek_write(), &siglen) <= 0)
            return TranslateLastOpenSslError();
    }
    if (!output->advance_write(siglen)) return KM_ERROR_UNKNOWN_ERROR;
    return KM_ERROR_OK;
}

keymaster_error_t Ed25519SignOperation::Begin(const AuthorizationSet& /* input_params */,
                                              AuthorizationSet* /* output_params */) {
    if (digest_ != KM_DIGEST_NONE) {
        // Ed25519 includes an internal digest, so no pre-digesting is supported.
        return KM_ERROR_UNSUPPORTED_DIGEST;
    }
    return GenerateRandom(reinterpret_cast<uint8_t*>(&operation_handle_),
                          (size_t)sizeof(operation_handle_));
}

keymaster_error_t Ed25519SignOperation::Update(const AuthorizationSet& /* additional_params */,
                                               const Buffer& input,
                                               AuthorizationSet* /* output_params */,
                                               Buffer* /* output */, size_t* input_consumed) {
    return StoreAllData(input, input_consumed);
}

keymaster_error_t Ed25519SignOperation::Finish(const AuthorizationSet& additional_params,
                                               const Buffer& input, const Buffer& /* signature */,
                                               AuthorizationSet* /* output_params */,
                                               Buffer* output) {
    if (!output) return KM_ERROR_OUTPUT_PARAMETER_NULL;

    keymaster_error_t error = UpdateForFinish(additional_params, input);
    if (error != KM_ERROR_OK) return error;

    if (!output->Reinitialize(ED25519_SIGNATURE_LEN)) {
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!EVP_DigestSignInit(ctx, /* pctx */ nullptr, /* digest */ nullptr, /* engine */ nullptr,
                            ecdsa_key_)) {
        EVP_MD_CTX_free(ctx);
        return TranslateLastOpenSslError();
    }
    size_t out_len = ED25519_SIGNATURE_LEN;
    if (!EVP_DigestSign(ctx, output->peek_write(), &out_len, data_.peek_read(),
                        data_.available_read())) {
        EVP_MD_CTX_free(ctx);
        return TranslateLastOpenSslError();
    }
    EVP_MD_CTX_free(ctx);
    output->advance_write(out_len);
    return KM_ERROR_OK;
}

keymaster_error_t Ed25519SignOperation::StoreAllData(const Buffer& input, size_t* input_consumed) {
    if ((data_.available_read() + input.available_read()) > MAX_ED25519_MSG_SIZE) {
        return KM_ERROR_INVALID_INPUT_LENGTH;
    }
    if (!data_.reserve(input.available_read())) {
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    }
    if (!data_.write(input.peek_read(), input.available_read())) {
        return KM_ERROR_UNKNOWN_ERROR;
    }

    *input_consumed = input.available_read();
    return KM_ERROR_OK;
}

keymaster_error_t EcdsaVerifyOperation::Begin(const AuthorizationSet& /* input_params */,
                                              AuthorizationSet* /* output_params */) {
    auto rc = GenerateRandom(reinterpret_cast<uint8_t*>(&operation_handle_),
                             (size_t)sizeof(operation_handle_));
    if (rc != KM_ERROR_OK) return rc;

    keymaster_error_t error = InitDigest();
    if (error != KM_ERROR_OK) return error;

    if (digest_ == KM_DIGEST_NONE) return KM_ERROR_OK;

    EVP_PKEY_CTX* pkey_ctx;
    if (EVP_DigestVerifyInit(digest_ctx_, &pkey_ctx, digest_algorithm_, nullptr /* engine */,
                             ecdsa_key_) != 1)
        return TranslateLastOpenSslError();
    return KM_ERROR_OK;
}

keymaster_error_t EcdsaVerifyOperation::Update(const AuthorizationSet& /* additional_params */,
                                               const Buffer& input,
                                               AuthorizationSet* /* output_params */,
                                               Buffer* /* output */, size_t* input_consumed) {
    if (digest_ == KM_DIGEST_NONE) return StoreData(input, input_consumed);

    if (EVP_DigestVerifyUpdate(digest_ctx_, input.peek_read(), input.available_read()) != 1)
        return TranslateLastOpenSslError();
    *input_consumed = input.available_read();
    return KM_ERROR_OK;
}

keymaster_error_t EcdsaVerifyOperation::Finish(const AuthorizationSet& additional_params,
                                               const Buffer& input, const Buffer& signature,
                                               AuthorizationSet* /* output_params */,
                                               Buffer* /* output */) {
    keymaster_error_t error = UpdateForFinish(additional_params, input);
    if (error != KM_ERROR_OK) return error;

    if (digest_ == KM_DIGEST_NONE) {
        UniquePtr<EC_KEY, EC_KEY_Delete> ecdsa(EVP_PKEY_get1_EC_KEY(ecdsa_key_));
        if (!ecdsa.get()) return TranslateLastOpenSslError();

        int result =
            ECDSA_verify(0 /* type -- ignored */, data_.peek_read(), data_.available_read(),
                         signature.peek_read(), signature.available_read(), ecdsa.get());
        if (result < 0)
            return TranslateLastOpenSslError();
        else if (result == 0)
            return KM_ERROR_VERIFICATION_FAILED;
    } else if (!EVP_DigestVerifyFinal(digest_ctx_, signature.peek_read(),
                                      signature.available_read()))
        return KM_ERROR_VERIFICATION_FAILED;

    return KM_ERROR_OK;
}

}  // namespace keymaster
