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

#ifndef TEE_KEYMASTER_IPC_H_
#define TEE_KEYMASTER_IPC_H_

#include <common.h>

#include <tee_client_api.h>
#include <keymaster/android_keymaster_messages.h>

#define KEYMASTER_SEND_BUF_SIZE_MAX 1 * 4096  // 4k
#define KEYMASTER_RECE_BUF_SIZE_MAX 2 * 4096  // 8K

keymaster_error_t tee_keymaster_connect(TEEC_Context* context,
                                        TEEC_Session* session, TEEC_UUID* uuid);
void tee_keymaster_disconnect(TEEC_Context* context, TEEC_Session* session);

keymaster_error_t translate_error(TEEC_Result err);
keymaster_error_t tee_keymaster_send(keystore_command command,
                                     TEEC_Context* context,
                                     TEEC_Session* session, TEEC_UUID* uuid,
                                     const keymaster::Serializable& request,
                                     keymaster::KeymasterResponse* response);

#endif  // TEE_KEYMASTER_IPC_H_
