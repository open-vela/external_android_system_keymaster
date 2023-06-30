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
typedef struct rsa_meth_st RSA_METHOD;
typedef struct ecdsa_method_st ECDSA_METHOD;
typedef struct BN_GENCB BN_GENCB;
typedef struct sha256_state_st SHA256_CTX;
typedef struct sha_state_st SHA_CTX;
typedef struct cbb_st CBB;
typedef struct ecdsa_sig_st ECDSA_SIG;

#ifdef __cplusplus
}
#endif

#if defined(BORINGSSL_PREFIX)
#define BSSL_NAMESPACE_BEGIN \
    namespace bssl {         \
        inline namespace BORINGSSL_PREFIX {
#define BSSL_NAMESPACE_END \
    }                      \
    }
#else
#define BSSL_NAMESPACE_BEGIN namespace bssl {
#define BSSL_NAMESPACE_END }
#endif

// MSVC doesn't set __cplusplus to 201103 to indicate C++11 support (see
// https://connect.microsoft.com/VisualStudio/feedback/details/763051/a-value-of-predefined-macro-cplusplus-is-still-199711l)
// so MSVC is just assumed to support C++11.
#if !defined(BORINGSSL_NO_CXX) && __cplusplus < 201103L && !defined(_MSC_VER)
#define BORINGSSL_NO_CXX
#endif

#if !defined(BORINGSSL_NO_CXX)

extern "C++" {

#include <memory>

// STLPort, used by some Android consumers, not have std::unique_ptr.
#if defined(_STLPORT_VERSION)
#define BORINGSSL_NO_CXX
#endif

} // extern C++
#endif // !BORINGSSL_NO_CXX

#if defined(BORINGSSL_NO_CXX)

#define BORINGSSL_MAKE_DELETER(type, deleter)
#define BORINGSSL_MAKE_UP_REF(type, up_ref_func)

#else

extern "C++" {

BSSL_NAMESPACE_BEGIN

namespace internal {

    // The Enable parameter is ignored and only exists so specializations can use
    // SFINAE.
    template <typename T, typename Enable = void>
    struct DeleterImpl {
    };

    template <typename T>
    struct Deleter {
        void operator()(T* ptr)
        {
            // Rather than specialize Deleter for each type, we specialize
            // DeleterImpl. This allows bssl::UniquePtr<T> to be used while only
            // including base.h as long as the destructor is not emitted. This matches
            // std::unique_ptr's behavior on forward-declared types.
            //
            // DeleterImpl itself is specialized in the corresponding module's header
            // and must be included to release an object. If not included, the compiler
            // will error that DeleterImpl<T> does not have a method Free.
            DeleterImpl<T>::Free(ptr);
        }
    };

    template <typename T, typename CleanupRet, void (*init)(T*),
        CleanupRet (*cleanup)(T*)>
    class StackAllocated {
    public:
        StackAllocated() { init(&ctx_); }
        ~StackAllocated() { cleanup(&ctx_); }

        StackAllocated(const StackAllocated&) = delete;
        StackAllocated& operator=(const StackAllocated&) = delete;

        T* get() { return &ctx_; }
        const T* get() const { return &ctx_; }

        T* operator->() { return &ctx_; }
        const T* operator->() const { return &ctx_; }

        void Reset()
        {
            cleanup(&ctx_);
            init(&ctx_);
        }

    private:
        T ctx_;
    };

    template <typename T, typename CleanupRet, void (*init)(T*),
        CleanupRet (*cleanup)(T*), void (*move)(T*, T*)>
    class StackAllocatedMovable {
    public:
        StackAllocatedMovable() { init(&ctx_); }
        ~StackAllocatedMovable() { cleanup(&ctx_); }

        StackAllocatedMovable(StackAllocatedMovable&& other)
        {
            init(&ctx_);
            move(&ctx_, &other.ctx_);
        }
        StackAllocatedMovable& operator=(StackAllocatedMovable&& other)
        {
            move(&ctx_, &other.ctx_);
            return *this;
        }

        T* get() { return &ctx_; }
        const T* get() const { return &ctx_; }

        T* operator->() { return &ctx_; }
        const T* operator->() const { return &ctx_; }

        void Reset()
        {
            cleanup(&ctx_);
            init(&ctx_);
        }

    private:
        T ctx_;
    };

} // namespace internal

#define BORINGSSL_MAKE_DELETER(type, deleter)             \
    namespace internal {                                  \
        template <>                                       \
        struct DeleterImpl<type> {                        \
            static void Free(type* ptr) { deleter(ptr); } \
        };                                                \
    }

// Holds ownership of heap-allocated BoringSSL structures. Sample usage:
//   bssl::UniquePtr<RSA> rsa(RSA_new());
//   bssl::UniquePtr<BIO> bio(BIO_new(BIO_s_mem()));
template <typename T>
using UniquePtr = std::unique_ptr<T, internal::Deleter<T>>;

#define BORINGSSL_MAKE_UP_REF(type, up_ref_func)             \
    inline UniquePtr<type> UpRef(type* v)                    \
    {                                                        \
        if (v != nullptr) {                                  \
            up_ref_func(v);                                  \
        }                                                    \
        return UniquePtr<type>(v);                           \
    }                                                        \
                                                             \
    inline UniquePtr<type> UpRef(const UniquePtr<type>& ptr) \
    {                                                        \
        return UpRef(ptr.get());                             \
    }

BSSL_NAMESPACE_END

} // extern C++

#endif // !BORINGSSL_NO_CXX

#endif // KEYMASTER_OPENSSL_BASE_H