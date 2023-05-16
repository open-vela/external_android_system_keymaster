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

#include <keymaster/contexts/tee_keymaster_ipc.h>
#include <keymaster/android_keymaster_messages.h>

#define LOG_TAG "TeeKeymasterIpc"
#include <log/log.h>

keymaster_error_t tee_keymaster_connect(TEEC_Context* context,
                                        TEEC_Session* session,
                                        TEEC_UUID* uuid) {
    ALOGV("[%s:%d]", __func__, __LINE__);

    uint32_t origin;
    TEEC_Result res;

    /* Initialize a context connecting us to the TEE */
    res = TEEC_InitializeContext(NULL, context);
    if (res != TEEC_SUCCESS) {
        ALOGE("TEEC_InitializeContext failed with code 0x%08" PRIx32 "\n", res);
        return translate_error(res);
    }

    /* Open session with the TA */
    res = TEEC_OpenSession(context, session, uuid, TEEC_LOGIN_PUBLIC, NULL,
                           NULL, &origin);
    if (res != TEEC_SUCCESS) {
        ALOGE("TEEC_Opensession failed with code 0x%08" PRIx32 " origin 0x%08" PRIx32 "\n", res,
              origin);
        return translate_error(res);
    }

    return KM_ERROR_OK;
}

void tee_keymaster_disconnect(TEEC_Context* context, TEEC_Session* session) {
    ALOGV("[%s:%d]", __func__, __LINE__);

    TEEC_CloseSession(session);
    TEEC_FinalizeContext(context);
}

keymaster_error_t translate_error(TEEC_Result err) {
    switch (err) {
        case TEEC_SUCCESS:
            return KM_ERROR_OK;
        case TEEC_ERROR_ACCESS_DENIED:
        case TEEC_ERROR_ACCESS_CONFLICT:
        case TEEC_ERROR_SECURITY:
            return KM_ERROR_SECURE_HW_ACCESS_DENIED;

        case TEEC_ERROR_CANCEL:
        case TEEC_ERROR_EXTERNAL_CANCEL:
            return KM_ERROR_OPERATION_CANCELLED;

        case TEEC_ERROR_NOT_IMPLEMENTED:
            return KM_ERROR_UNIMPLEMENTED;

        case TEEC_ERROR_OUT_OF_MEMORY:
            return KM_ERROR_MEMORY_ALLOCATION_FAILED;

        case TEEC_ERROR_BUSY:
            return KM_ERROR_SECURE_HW_BUSY;

        case TEEC_ERROR_COMMUNICATION:
            return KM_ERROR_SECURE_HW_COMMUNICATION_FAILED;

        case TEEC_ERROR_SHORT_BUFFER:
            return KM_ERROR_INVALID_INPUT_LENGTH;

        default:
            return KM_ERROR_UNKNOWN_ERROR;
    }
}

keymaster_error_t tee_keymaster_send(keystore_command command,
                                     TEEC_Context* context,
                                     TEEC_Session* session, TEEC_UUID* uuid,
                                     const keymaster::Serializable& request,
                                     keymaster::KeymasterResponse* response) {
    ALOGV("[%s:%d][%d]", __func__, __LINE__, command);

    uint32_t req_size = request.SerializedSize();
    if (req_size > KEYMASTER_SEND_BUF_SIZE_MAX) {
        ALOGE("Request too big: %" PRIu32 " Max size: %d", req_size, KEYMASTER_SEND_BUF_SIZE_MAX);
        return KM_ERROR_INVALID_INPUT_LENGTH;
    }

    TEEC_Result res;
    TEEC_Operation op;
    uint32_t origin;
    uint8_t* buffer;
    TEEC_SharedMemory req_shm;
    TEEC_SharedMemory rsp_shm;
    keymaster_error_t keymaster_res = KM_ERROR_OK;

    // construct req_shm
    req_shm.size = request.SerializedSize();
    req_shm.flags = TEEC_MEM_INPUT;

    res = TEEC_AllocateSharedMemory(context, &req_shm);
    if (res != TEEC_SUCCESS) {
        ALOGE("[%d]TEEC_AllocateSharedMemory failed with code 0x%08" PRIx32 "\n",
              command, res);
        goto exit;
    }
    memset(req_shm.buffer, 0, req_shm.size);
    request.Serialize((uint8_t*)req_shm.buffer,
                      (uint8_t*)req_shm.buffer + req_shm.size);

    // construct rsp_shm
    rsp_shm.size = KEYMASTER_RECE_BUF_SIZE_MAX;
    rsp_shm.flags = TEEC_MEM_OUTPUT;
    res = TEEC_AllocateSharedMemory(context, &rsp_shm);
    if (res != TEEC_SUCCESS) {
        ALOGE("[%d]TEEC_AllocateSharedMemory failed with code 0x%08" PRIx32 "\n",
              command, res);
        goto exit_free_req_mem;
    }
    memset(rsp_shm.buffer, 0, rsp_shm.size);

    // construct op
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_WHOLE, TEEC_MEMREF_WHOLE,
                                     TEEC_NONE, TEEC_NONE);
    op.params[0].memref.parent = &req_shm;
    op.params[1].memref.parent = &rsp_shm;

    // run command
    res = TEEC_InvokeCommand(session, command, &op, &origin);
    if (res != TEEC_SUCCESS) {
        ALOGE(
            "[%d]TEEC_InvokeCommand failed with code 0x%08" PRIx32 " origin 0x%08" PRIx32 ", "
            "reconnect automatic.\n",
            command, res, origin);
        tee_keymaster_disconnect(context, session);
        tee_keymaster_connect(context, session, uuid);
        goto exit_free_mem;
    }

    // deconstruct response
    buffer = (uint8_t*)rsp_shm.buffer;
    if (!response->Deserialize((const uint8_t**)&buffer,
                               buffer + rsp_shm.size)) {
        ALOGE("[%d]Error deserializing response of size %d\n", command,
              (int)rsp_shm.size);
        keymaster_res = KM_ERROR_UNKNOWN_ERROR;
    } else if (response->error != KM_ERROR_OK) {
        ALOGE("[%d]Response of size %d contained error code %d\n", command,
              (int)rsp_shm.size, (int)response->error);
        keymaster_res = response->error;
    }

exit_free_mem:
    TEEC_ReleaseSharedMemory(&rsp_shm);
exit_free_req_mem:
    TEEC_ReleaseSharedMemory(&req_shm);
exit:
    if (keymaster_res != KM_ERROR_OK) {
        return keymaster_res;
    }
    return translate_error(res);
}