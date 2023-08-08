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

#ifndef OPENSSL_SSL_BASE_H
#define OPENSSL_SSL_BASE_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <openssl/base.h>
#include <openssl/ecdsa.h>

#define BSSL_NAMESPACE_BEGIN namespace bssl {
#define BSSL_NAMESPACE_END }

extern "C++" {

#include <memory>

// STLPort, used by some Android consumers, not have std::unique_ptr.
#if defined(_STLPORT_VERSION)
#define BORINGSSL_NO_CXX
#endif

} // extern C++

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


#if !defined(BORINGSSL_NO_CXX)
extern "C++" {

BSSL_NAMESPACE_BEGIN

BORINGSSL_MAKE_DELETER(BIGNUM, BN_free)

BORINGSSL_MAKE_DELETER(EVP_CIPHER_CTX, EVP_CIPHER_CTX_free)

using ScopedEVP_CIPHER_CTX =
    internal::StackAllocated<EVP_CIPHER_CTX, int, EVP_CIPHER_CTX_init,
                             EVP_CIPHER_CTX_cleanup>;

BORINGSSL_MAKE_DELETER(EC_KEY, EC_KEY_free)
BORINGSSL_MAKE_DELETER(EC_POINT, EC_POINT_free)
BORINGSSL_MAKE_DELETER(EC_GROUP, EC_GROUP_free)

BORINGSSL_MAKE_DELETER(ECDSA_SIG, ECDSA_SIG_free)

BORINGSSL_MAKE_DELETER(EVP_PKEY, EVP_PKEY_free)
BORINGSSL_MAKE_DELETER(EVP_PKEY_CTX, EVP_PKEY_CTX_free)

BSSL_NAMESPACE_END

} // extern C++
#endif

#endif // !BORINGSSL_NO_CXX

#endif // OPENSSL_SSL_BASE_H