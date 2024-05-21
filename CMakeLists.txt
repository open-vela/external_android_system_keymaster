#
# Copyright (C) 2023 Xiaomi Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License. You may obtain a copy of
# the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under
# the License.
#
if(CONFIG_ANDROID_KEYMASTER)

  set_property(
    TARGET nuttx
    APPEND
    PROPERTY NUTTX_INCLUDE_DIRECTORIES ${CMAKE_CURRENT_LIST_DIR}/include)

  nuttx_add_library(android_keymaster STATIC)

  set(FLAGS -Wno-shadow -Wno-undef -DKEYMASTER_UNIT_TEST_BUILD)

  set(INCDIR ${CMAKE_CURRENT_LIST_DIR})

  set(SRCS
      android_keymaster/android_keymaster_messages.cpp
      android_keymaster/android_keymaster_utils.cpp
      android_keymaster/authorization_set.cpp
      android_keymaster/keymaster_configuration.cpp
      android_keymaster/keymaster_tags.cpp
      android_keymaster/serializable.cpp
      android_keymaster/logger.cpp
      km_mbedtls/err.cpp
      km_openssl/openssl_utils.cpp)

  if(CONFIG_KEYMASTER_TEE)

    list(APPEND INCDIR
         ${NUTTX_APPS_DIR}/external/optee/kmgk/kmgk/keymaster/ta/include)

    list(
      APPEND
      FLAGS
      -DKEYMASTER_SEND_BUF_SIZE_MAX=${CONFIG_KEYMASTER_TEE_SEND_BUF_MAX}
      -DKEYMASTER_FINSIH_INPUT_LENGHT_MAX=${CONFIG_KEYMASTER_TEE_SEND_BUF_MAX}
      -DKEYMASTER_RECE_BUF_SIZE_MAX=${CONFIG_KEYMASTER_TEE_RECV_BUF_MAX})

    list(APPEND SRCS contexts/tee_keymaster_device.cpp
         contexts/tee_keymaster_ipc.cpp)

  endif()

  if(CONFIG_KEYMASTER_SOFTWARE)
    list(
      APPEND
      SRCS
      android_keymaster/android_keymaster.cpp
      android_keymaster/keymaster_enforcement.cpp
      android_keymaster/operation.cpp
      android_keymaster/operation_table.cpp
      android_keymaster/pure_soft_secure_key_storage.cpp
      contexts/pure_soft_remote_provisioning_context.cpp
      contexts/soft_attestation_cert.cpp
      contexts/soft_attestation_context.cpp
      contexts/soft_keymaster_context.cpp
      contexts/soft_keymaster_device.cpp
      contexts/soft_keymaster_logger.cpp
      cppcose/cppcose.cpp
      key_blob_utils/auth_encrypted_key_blob.cpp
      key_blob_utils/integrity_assured_key_blob.cpp
      key_blob_utils/ocb_utils.cpp
      key_blob_utils/software_keyblobs.cpp
      km_openssl/aes_operation.cpp
      km_openssl/asymmetric_key.cpp
      km_openssl/asymmetric_key_factory.cpp
      km_openssl/aes_key.cpp
      km_openssl/block_cipher_operation.cpp
      km_openssl/curve25519_key.cpp
      km_openssl/certificate_utils.cpp
      km_openssl/ecdsa_operation.cpp
      km_openssl/ec_key_factory.cpp
      km_openssl/ec_key.cpp
      km_openssl/ecdh_operation.cpp
      km_openssl/hmac.cpp
      km_openssl/hmac_key.cpp
      km_openssl/hmac_operation.cpp
      km_openssl/triple_des_operation.cpp
      km_openssl/triple_des_key.cpp
      km_openssl/rsa_key.cpp
      km_openssl/rsa_key_factory.cpp
      km_openssl/rsa_operation.cpp
      km_openssl/software_random_source.cpp
      km_openssl/symmetric_key.cpp
      legacy_support/keymaster1_engine.cpp
      key_blob_utils/ocb.c)
  endif()

  if(CONFIG_KEYMASTER_TEST)
    nuttx_add_application(
      NAME
      keymaster_gtest
      STACKSIZE
      ${CONFIG_KEYMASTER_TEST_STACKSIZE}
      PRIORITY
      ${CONFIG_KEYMASTER_TEST_PRIORITY}
      SRCS
      tests/gtest_main_entry.cpp
      COMPILE_FLAGS
      ${FLAGS}
      -DKEYMASTER_NAME_TAGS
      INCLUDE_DIRECTORIES
      ${INCDIR}
      DEPENDS
      android_keymaster)
  endif()

  target_sources(android_keymaster PRIVATE ${SRCS})
  target_include_directories(android_keymaster PRIVATE ${INCDIR})
  target_compile_options(android_keymaster PRIVATE ${FLAGS})

endif()
