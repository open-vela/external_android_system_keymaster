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

#include <common.h>
#include <keymaster/tee_keymaster_device.h>
#include <keymaster/contexts/tee_keymaster_ipc.h>
#include <keymaster/android_keymaster_messages.h>

#define LOG_TAG "TeeKeymasterDevice"
#include <log/log.h>

#ifndef KEYMASTER_FINSIH_INPUT_LENGHT_MAX
#define KEYMASTER_FINSIH_INPUT_LENGHT_MAX 2048
#endif

namespace keymaster {
TeeKeymasterDevice::TeeKeymasterDevice(const hw_module_t* module) {
    ALOGV("[%s:%d]", __func__, __LINE__);
    device_ = {};

    device_.common.tag = HARDWARE_DEVICE_TAG;
    device_.common.version = 1;
    device_.common.module = const_cast<hw_module_t*>(module);
    device_.common.close = close_device;

    device_.flags = 0;
    device_.context = this;
    device_.configure = configure;
    device_.add_rng_entropy = add_rng_entropy;
    device_.generate_key = generate_key;
    device_.get_key_characteristics = get_key_characteristics;
    device_.import_key = import_key;
    device_.export_key = export_key;
    device_.attest_key = attest_key;
    device_.upgrade_key = upgrade_key;
    device_.delete_key = delete_key;
    device_.delete_all_keys = delete_all_keys;
    device_.begin = begin;
    device_.update = update;
    device_.finish = finish;
    device_.abort = abort;

    uuid_ = TA_KEYMASTER_UUID;
    message_version_ = MessageVersion(KmVersion::KEYMASTER_2);

    tee_keymaster_connect(&context_, &session_, &uuid_);
}

TeeKeymasterDevice::~TeeKeymasterDevice() {
    ALOGV("[%s:%d]", __func__, __LINE__);

    tee_keymaster_disconnect(&context_, &session_);
}

namespace {

// Allocates a new buffer with malloc and copies the contents of |buffer| to it.
// Caller takes ownership of the returned buffer.
uint8_t* DuplicateBuffer(const uint8_t* buffer, size_t size) {
    uint8_t* tmp = reinterpret_cast<uint8_t*>(malloc(size));
    if (tmp) {
        memcpy(tmp, buffer, size);
    }
    return tmp;
}

template <typename RequestType>
void AddClientAndAppData(const keymaster_blob_t* client_id,
                         const keymaster_blob_t* app_data,
                         RequestType* request) {
    request->additional_params.Clear();
    if (client_id && client_id->data_length > 0) {
        request->additional_params.push_back(TAG_APPLICATION_ID, *client_id);
    }
    if (app_data && app_data->data_length > 0) {
        request->additional_params.push_back(TAG_APPLICATION_DATA, *app_data);
    }
}

}  //  unnamed namespace

keymaster_error_t TeeKeymasterDevice::configure(
    const keymaster_key_param_set_t* params) {
    ALOGV("[%s:%d]", __func__, __LINE__);

    if (!params) {
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }

    keymaster_error_t err;
    AuthorizationSet params_copy(*params);
    ConfigureRequest request(message_version_);
    ConfigureResponse response(message_version_);

    if (!params_copy.GetTagValue(TAG_OS_VERSION, &request.os_version) ||
        !params_copy.GetTagValue(TAG_OS_PATCHLEVEL, &request.os_patchlevel)) {
        ALOGE("Configuration parameters must contain OS version and patch level");
        return KM_ERROR_INVALID_ARGUMENT;
    }

    err = tee_keymaster_send(KM_CONFIGURE, &context_, &session_,
                             &uuid_, request, &response);
    if (err != KM_ERROR_OK) {
        return err;
    }

    return KM_ERROR_OK;
}

keymaster_error_t TeeKeymasterDevice::add_rng_entropy(const uint8_t* data,
                                                      size_t data_length) {
    // return fake KM_ERROR_OK value
    // TA don't support this interface yet, but keystore use it
    return KM_ERROR_OK;
}

keymaster_error_t TeeKeymasterDevice::generate_key(
    const keymaster_key_param_set_t* params, keymaster_key_blob_t* key_blob,
    keymaster_key_characteristics_t* characteristics) {
    ALOGV("[%s:%d]", __func__, __LINE__);

    if (!params) {
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    if (!key_blob) {
        return KM_ERROR_OUTPUT_PARAMETER_NULL;
    }

    keymaster_error_t err;
    GenerateKeyRequest request(message_version_);
    GenerateKeyResponse response(message_version_);

    request.key_description.Reinitialize(*params);

    err = tee_keymaster_send(KM_GENERATE_KEY, &context_, &session_,
                             &uuid_, request, &response);
    if (err != KM_ERROR_OK) {
        return err;
    }

    key_blob->key_material_size = response.key_blob.key_material_size;
    key_blob->key_material = DuplicateBuffer(
        response.key_blob.key_material, response.key_blob.key_material_size);
    if (!key_blob->key_material) {
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    }

    if (characteristics) {
        response.enforced.CopyToParamSet(&characteristics->hw_enforced);
        response.unenforced.CopyToParamSet(&characteristics->sw_enforced);
    }

    return KM_ERROR_OK;
}

keymaster_error_t TeeKeymasterDevice::get_key_characteristics(
    const keymaster_key_blob_t* key_blob, const keymaster_blob_t* client_id,
    const keymaster_blob_t* app_data,
    keymaster_key_characteristics_t* character) {
    ALOGV("[%s:%d]", __func__, __LINE__);

    if (!key_blob || !key_blob->key_material) {
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    if (!character) {
        return KM_ERROR_OUTPUT_PARAMETER_NULL;
    }

    keymaster_error_t err;
    GetKeyCharacteristicsRequest request(message_version_);
    GetKeyCharacteristicsResponse response(message_version_);

    err = tee_keymaster_send(KM_GET_KEY_CHARACTERISTICS, &context_,
                             &session_, &uuid_, request, &response);
    if (err != KM_ERROR_OK) {
        return err;
    }

    response.enforced.CopyToParamSet(&character->hw_enforced);
    response.unenforced.CopyToParamSet(&character->sw_enforced);

    return KM_ERROR_OK;
}

keymaster_error_t TeeKeymasterDevice::import_key(
    const keymaster_key_param_set_t* params, keymaster_key_format_t key_format,
    const keymaster_blob_t* key_data, keymaster_key_blob_t* key_blob,
    keymaster_key_characteristics_t* characteristics) {
    return KM_ERROR_UNIMPLEMENTED;
}

keymaster_error_t TeeKeymasterDevice::export_key(
    keymaster_key_format_t export_format,
    const keymaster_key_blob_t* key_to_export,
    const keymaster_blob_t* client_id, const keymaster_blob_t* app_data,
    keymaster_blob_t* export_data) {
    return KM_ERROR_UNIMPLEMENTED;
}

keymaster_error_t TeeKeymasterDevice::attest_key(
    const keymaster_key_blob_t* key_to_attest,
    const keymaster_key_param_set_t* attest_params,
    keymaster_cert_chain_t* cert_chain) {
    return KM_ERROR_UNIMPLEMENTED;
}

keymaster_error_t TeeKeymasterDevice::upgrade_key(
    const keymaster_key_blob_t* key_to_upgrade,
    const keymaster_key_param_set_t* upgrade_params,
    keymaster_key_blob_t* upgraded_key) {
    return KM_ERROR_UNIMPLEMENTED;
}

keymaster_error_t TeeKeymasterDevice::begin(
    keymaster_purpose_t purpose, const keymaster_key_blob_t* key,
    const keymaster_key_param_set_t* in_params,
    keymaster_key_param_set_t* out_params,
    keymaster_operation_handle_t* operation_handle) {
    ALOGV("[%s:%d]", __func__, __LINE__);

    if (!key || !key->key_material) {
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    if (!operation_handle) {
        return KM_ERROR_OUTPUT_PARAMETER_NULL;
    }

    if (out_params) {
        *out_params = {};
    }

    keymaster_error_t err;
    BeginOperationRequest request(message_version_);
    BeginOperationResponse response(message_version_);

    request.purpose = purpose;
    request.SetKeyMaterial(*key);
    request.additional_params.Reinitialize(*in_params);

    err = tee_keymaster_send(KM_BEGIN, &context_, &session_, &uuid_,
                             request, &response);
    if (err != KM_ERROR_OK) {
        return err;
    }

    if (response.output_params.size() > 0) {
        if (out_params) {
            response.output_params.CopyToParamSet(out_params);
        } else {
            return KM_ERROR_OUTPUT_PARAMETER_NULL;
        }
    }
    *operation_handle = response.op_handle;

    return KM_ERROR_OK;
}

keymaster_error_t TeeKeymasterDevice::update(
    keymaster_operation_handle_t operation_handle,
    const keymaster_key_param_set_t* in_params, const keymaster_blob_t* input,
    size_t* input_consumed, keymaster_key_param_set_t* out_params,
    keymaster_blob_t* output) {
    ALOGV("[%s:%d]", __func__, __LINE__);

    if (!input) {
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    if (!input_consumed) {
        return KM_ERROR_OUTPUT_PARAMETER_NULL;
    }

    if (out_params) {
        *out_params = {};
    }
    if (output) {
        *output = {};
    }

    keymaster_error_t err;
    UpdateOperationRequest request(message_version_);
    UpdateOperationResponse response(message_version_);

    request.op_handle = operation_handle;
    if (in_params) {
        request.additional_params.Reinitialize(*in_params);
    }
    if (input && input->data_length > 0) {
        size_t max_input_size =
            KEYMASTER_SEND_BUF_SIZE_MAX - request.SerializedSize();
        request.input.Reinitialize(
            input->data, std::min(input->data_length, max_input_size));
    }

    err = tee_keymaster_send(KM_UPDATE, &context_, &session_, &uuid_,
                             request, &response);
    if (err != KM_ERROR_OK) {
        return err;
    }

    if (response.output_params.size() > 0) {
        if (out_params) {
            response.output_params.CopyToParamSet(out_params);
        } else {
            return KM_ERROR_OUTPUT_PARAMETER_NULL;
        }
    }
    *input_consumed = response.input_consumed;
    if (output) {
        output->data_length = response.output.available_read();
        output->data =
            DuplicateBuffer(response.output.peek_read(), output->data_length);
        if (!output->data) {
            return KM_ERROR_MEMORY_ALLOCATION_FAILED;
        }
    } else if (response.output.available_read() > 0) {
        return KM_ERROR_OUTPUT_PARAMETER_NULL;
    }

    return KM_ERROR_OK;
}

keymaster_error_t TeeKeymasterDevice::finish(
    keymaster_operation_handle_t operation_handle,
    const keymaster_key_param_set_t* in_params, const keymaster_blob_t* input,
    const keymaster_blob_t* signature, keymaster_key_param_set_t* out_params,
    keymaster_blob_t* output) {
    ALOGV("[%s:%d]", __func__, __LINE__);

    if (input && input->data_length > KEYMASTER_FINSIH_INPUT_LENGHT_MAX) {
        ALOGE("%zu-byte input to finish; only %zu bytes allowed",
              input->data_length, KEYMASTER_FINSIH_INPUT_LENGHT_MAX);
        return KM_ERROR_INVALID_INPUT_LENGTH;
    }

    if (out_params) {
        *out_params = {};
    }
    if (output) {
        *output = {};
    }

    keymaster_error_t err;
    FinishOperationRequest request(message_version_);
    FinishOperationResponse response(message_version_);

    request.op_handle = operation_handle;
    if (signature && signature->data && signature->data_length > 0) {
        request.signature.Reinitialize(signature->data, signature->data_length);
    }
    if (input && input->data && input->data_length) {
        request.input.Reinitialize(input->data, input->data_length);
    }
    if (in_params) {
        request.additional_params.Reinitialize(*in_params);
    }

    err = tee_keymaster_send(KM_FINISH, &context_, &session_, &uuid_,
                             request, &response);
    if (err != KM_ERROR_OK) {
        return err;
    }

    if (response.output_params.size() > 0) {
        if (out_params) {
            response.output_params.CopyToParamSet(out_params);
        } else {
            return KM_ERROR_OUTPUT_PARAMETER_NULL;
        }
    }
    if (output) {
        output->data_length = response.output.available_read();
        output->data =
            DuplicateBuffer(response.output.peek_read(), output->data_length);
        if (!output->data) {
            return KM_ERROR_MEMORY_ALLOCATION_FAILED;
        }
    } else if (response.output.available_read() > 0) {
        return KM_ERROR_OUTPUT_PARAMETER_NULL;
    }

    return KM_ERROR_OK;
}

keymaster_error_t TeeKeymasterDevice::abort(
    keymaster_operation_handle_t operation_handle) {
    return KM_ERROR_UNIMPLEMENTED;
}

keymaster_error_t TeeKeymasterDevice::delete_key(
    const keymaster_key_blob_t* key) {
    ALOGV("[%s:%d]", __func__, __LINE__);

    if (!key || !key->key_material) return KM_ERROR_UNEXPECTED_NULL_POINTER;

    DeleteKeyRequest request(message_version_);
    DeleteKeyResponse response(message_version_);
    request.SetKeyMaterial(*key);

    return tee_keymaster_send(KM_DELETE_KEY, &context_, &session_,
                              &uuid_, request, &response);
}

keymaster_error_t TeeKeymasterDevice::delete_all_keys() {
    return KM_ERROR_UNIMPLEMENTED;
}

static inline TeeKeymasterDevice* convert_device(
    const keymaster2_device_t* dev) {
    return reinterpret_cast<TeeKeymasterDevice*>(dev->context);
}

/* static */
int TeeKeymasterDevice::close_device(hw_device_t* dev) {
    delete convert_device(reinterpret_cast<keymaster2_device_t*>(dev));
    return 0;
}

/* static */
keymaster_error_t TeeKeymasterDevice::configure(
    const keymaster2_device_t* dev, const keymaster_key_param_set_t* params) {
    return convert_device(dev)->configure(params);
}

/* static */
keymaster_error_t TeeKeymasterDevice::add_rng_entropy(
    const keymaster2_device_t* dev, const uint8_t* data, size_t data_length) {
    return convert_device(dev)->add_rng_entropy(data, data_length);
}

/* static */
keymaster_error_t TeeKeymasterDevice::generate_key(
    const keymaster2_device_t* dev, const keymaster_key_param_set_t* params,
    keymaster_key_blob_t* key_blob,
    keymaster_key_characteristics_t* characteristics) {
    return convert_device(dev)->generate_key(params, key_blob, characteristics);
}

/* static */
keymaster_error_t TeeKeymasterDevice::get_key_characteristics(
    const keymaster2_device_t* dev, const keymaster_key_blob_t* key_blob,
    const keymaster_blob_t* client_id, const keymaster_blob_t* app_data,
    keymaster_key_characteristics_t* characteristics) {
    return convert_device(dev)->get_key_characteristics(
        key_blob, client_id, app_data, characteristics);
}

/* static */
keymaster_error_t TeeKeymasterDevice::import_key(
    const keymaster2_device_t* dev, const keymaster_key_param_set_t* params,
    keymaster_key_format_t key_format, const keymaster_blob_t* key_data,
    keymaster_key_blob_t* key_blob,
    keymaster_key_characteristics_t* characteristics) {
    return convert_device(dev)->import_key(params, key_format, key_data,
                                           key_blob, characteristics);
}

/* static */
keymaster_error_t TeeKeymasterDevice::export_key(
    const keymaster2_device_t* dev, keymaster_key_format_t export_format,
    const keymaster_key_blob_t* key_to_export,
    const keymaster_blob_t* client_id, const keymaster_blob_t* app_data,
    keymaster_blob_t* export_data) {
    return convert_device(dev)->export_key(export_format, key_to_export,
                                           client_id, app_data, export_data);
}

/* static */
keymaster_error_t TeeKeymasterDevice::attest_key(
    const keymaster2_device_t* dev, const keymaster_key_blob_t* key_to_attest,
    const keymaster_key_param_set_t* attest_params,
    keymaster_cert_chain_t* cert_chain) {
    return convert_device(dev)->attest_key(key_to_attest, attest_params,
                                           cert_chain);
}

/* static */
keymaster_error_t TeeKeymasterDevice::upgrade_key(
    const keymaster2_device_t* dev, const keymaster_key_blob_t* key_to_upgrade,
    const keymaster_key_param_set_t* upgrade_params,
    keymaster_key_blob_t* upgraded_key) {
    return convert_device(dev)->upgrade_key(key_to_upgrade, upgrade_params,
                                            upgraded_key);
}

/* static */
keymaster_error_t TeeKeymasterDevice::begin(
    const keymaster2_device_t* dev, keymaster_purpose_t purpose,
    const keymaster_key_blob_t* key, const keymaster_key_param_set_t* in_params,
    keymaster_key_param_set_t* out_params,
    keymaster_operation_handle_t* operation_handle) {
    return convert_device(dev)->begin(purpose, key, in_params, out_params,
                                      operation_handle);
}

/* static */
keymaster_error_t TeeKeymasterDevice::update(
    const keymaster2_device_t* dev,
    keymaster_operation_handle_t operation_handle,
    const keymaster_key_param_set_t* in_params, const keymaster_blob_t* input,
    size_t* input_consumed, keymaster_key_param_set_t* out_params,
    keymaster_blob_t* output) {
    return convert_device(dev)->update(operation_handle, in_params, input,
                                       input_consumed, out_params, output);
}

/* static */
keymaster_error_t TeeKeymasterDevice::finish(
    const keymaster2_device_t* dev,
    keymaster_operation_handle_t operation_handle,
    const keymaster_key_param_set_t* in_params, const keymaster_blob_t* input,
    const keymaster_blob_t* signature, keymaster_key_param_set_t* out_params,
    keymaster_blob_t* output) {
    return convert_device(dev)->finish(operation_handle, in_params, input,
                                       signature, out_params, output);
}

/* static */
keymaster_error_t TeeKeymasterDevice::abort(
    const keymaster2_device_t* dev,
    keymaster_operation_handle_t operation_handle) {
    return convert_device(dev)->abort(operation_handle);
}

/* static */
keymaster_error_t TeeKeymasterDevice::delete_key(
    const keymaster2_device_t* dev, const keymaster_key_blob_t* key) {
    return convert_device(dev)->delete_key(key);
}

/* static */
keymaster_error_t TeeKeymasterDevice::delete_all_keys(
    const keymaster2_device_t* dev) {
    return convert_device(dev)->delete_all_keys();
}

}  // namespace keymaster
