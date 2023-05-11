#
# Copyright (C) 2023 Xiaomi Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

include $(APPDIR)/Make.defs

CXXEXT = .cpp
CXXFLAGS += -DKEYMASTER_UNIT_TEST_BUILD

CXXSRCS += android_keymaster/android_keymaster_messages.cpp
CXXSRCS += android_keymaster/android_keymaster_utils.cpp
CXXSRCS += android_keymaster/authorization_set.cpp
CXXSRCS += android_keymaster/keymaster_configuration.cpp
CXXSRCS += android_keymaster/keymaster_tags.cpp
CXXSRCS += android_keymaster/serializable.cpp
CXXSRCS += android_keymaster/logger.cpp
CXXSRCS += km_mbedtls/aes.cpp
CXXSRCS += km_mbedtls/asn1.cpp
CXXSRCS += km_mbedtls/bn.cpp
CXXSRCS += km_mbedtls/bytestring.cpp
CXXSRCS += km_mbedtls/cipher.cpp
CXXSRCS += km_mbedtls/curve25519.cpp
CXXSRCS += km_mbedtls/digest.cpp
CXXSRCS += km_mbedtls/ecdsa.cpp
CXXSRCS += km_mbedtls/engine.cpp
CXXSRCS += km_mbedtls/ec.cpp
CXXSRCS += km_mbedtls/ec_key.cpp
CXXSRCS += km_mbedtls/err.cpp
CXXSRCS += km_mbedtls/evp.cpp
CXXSRCS += km_mbedtls/hmac.cpp
CXXSRCS += km_mbedtls/hkdf.cpp
CXXSRCS += km_mbedtls/md5.cpp
CXXSRCS += km_mbedtls/mem.cpp
CXXSRCS += km_mbedtls/rsa.cpp
CXXSRCS += km_mbedtls/rand.cpp
CXXSRCS += km_mbedtls/pbkdf.cpp
CXXSRCS += km_mbedtls/obj.cpp
CXXSRCS += km_mbedtls/x509.cpp
CXXSRCS += km_mbedtls/sha.cpp
CXXSRCS += km_openssl/openssl_utils.cpp

ifneq ($(CONFIG_KEYMASTER_TEE),)
# TA head file
CXXFLAGS += ${INCDIR_PREFIX}$(APPDIR)/external/kmgk/kmgk/keymaster/ta/include

CXXFLAGS += ${DEFINE_PREFIX}KEYMASTER_SEND_BUF_SIZE_MAX=$(CONFIG_KEYMASTER_TEE_SEND_BUF_MAX)
CXXFLAGS += ${DEFINE_PREFIX}KEYMASTER_FINSIH_INPUT_LENGHT_MAX=$(CONFIG_KEYMASTER_TEE_SEND_BUF_MAX)
CXXFLAGS += ${DEFINE_PREFIX}KEYMASTER_RECE_BUF_SIZE_MAX=$(CONFIG_KEYMASTER_TEE_RECV_BUF_MAX)

CXXSRCS += contexts/tee_keymaster_device.cpp
CXXSRCS += contexts/tee_keymaster_ipc.cpp
endif

ifneq ($(CONFIG_KEYMASTER_SOFTWARE),)

CXXSRCS += android_keymaster/android_keymaster.cpp
CXXSRCS += android_keymaster/keymaster_enforcement.cpp
CXXSRCS += android_keymaster/operation.cpp
CXXSRCS += android_keymaster/operation_table.cpp
CXXSRCS += android_keymaster/pure_soft_secure_key_storage.cpp
CXXSRCS += contexts/pure_soft_remote_provisioning_context.cpp
CXXSRCS += contexts/soft_attestation_cert.cpp
CXXSRCS += contexts/soft_attestation_context.cpp
CXXSRCS += contexts/soft_keymaster_context.cpp
CXXSRCS += contexts/soft_keymaster_device.cpp
CXXSRCS += contexts/soft_keymaster_logger.cpp
CXXSRCS += cppcose/cppcose.cpp
CXXSRCS += key_blob_utils/auth_encrypted_key_blob.cpp
CXXSRCS += key_blob_utils/integrity_assured_key_blob.cpp
CXXSRCS += key_blob_utils/ocb_utils.cpp
CXXSRCS += key_blob_utils/software_keyblobs.cpp
CXXSRCS += km_openssl/aes_operation.cpp
CXXSRCS += km_openssl/asymmetric_key.cpp
CXXSRCS += km_openssl/asymmetric_key_factory.cpp
CXXSRCS += km_openssl/aes_key.cpp
CXXSRCS += km_openssl/block_cipher_operation.cpp
CXXSRCS += km_openssl/curve25519_key.cpp
CXXSRCS += km_openssl/certificate_utils.cpp
CXXSRCS += km_openssl/ecdsa_operation.cpp
CXXSRCS += km_openssl/ec_key_factory.cpp
CXXSRCS += km_openssl/ec_key.cpp
CXXSRCS += km_openssl/ecdh_operation.cpp
CXXSRCS += km_openssl/hmac.cpp
CXXSRCS += km_openssl/hmac_key.cpp
CXXSRCS += km_openssl/hmac_operation.cpp
CXXSRCS += km_openssl/triple_des_operation.cpp
CXXSRCS += km_openssl/triple_des_key.cpp
CXXSRCS += km_openssl/rsa_key.cpp
CXXSRCS += km_openssl/rsa_key_factory.cpp
CXXSRCS += km_openssl/rsa_operation.cpp
CXXSRCS += km_openssl/software_random_source.cpp
CXXSRCS += km_openssl/symmetric_key.cpp
CXXSRCS += legacy_support/keymaster1_engine.cpp

CSRCS += key_blob_utils/ocb.c
endif

CXXFLAGS += -Wno-shadow
CFLAGS   += -Wno-undef

ifneq ($(CONFIG_KEYMASTER_TEST),)

CXXFLAGS += -DKEYMASTER_NAME_TAGS

PROGNAME += keymaster_gtest
MAINSRC = tests/gtest_main_entry.cpp
PRIORITY  = $(CONFIG_KEYMASTER_TEST_PRIORITY)
STACKSIZE = $(CONFIG_KEYMASTER_TEST_STACKSIZE)
endif

include $(APPDIR)/Application.mk
