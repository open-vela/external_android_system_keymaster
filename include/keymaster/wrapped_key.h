/*
 * Copyright 2017 The Android Open Source Project
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

#ifndef SYSTEM_KEYMASTER_WRAPPED_KEY_H_
#define SYSTEM_KEYMASTER_WRAPPED_KEY_H_

#include <hardware/keymaster_defs.h>

#include <keymaster/authorization_set.h>

namespace keymaster {

keymaster_error_t build_wrapped_key(const KeymasterKeyBlob& encrypted_ephemeral_key,
                                    const KeymasterBlob& iv, keymaster_key_format_t key_format,
                                    const KeymasterKeyBlob& secure_key, const KeymasterBlob& tag,
                                    const AuthorizationSet& authorization_list,
                                    KeymasterKeyBlob* der_wrapped_key);

keymaster_error_t parse_wrapped_key(const KeymasterKeyBlob& wrapped_key, KeymasterBlob* iv,
                                    KeymasterKeyBlob* transit_key, KeymasterKeyBlob* secure_key,
                                    KeymasterBlob* tag, AuthorizationSet* auth_list,
                                    keymaster_key_format_t* key_format,
                                    KeymasterBlob* wrapped_key_description);

}  // namespace keymaster

#endif  // SYSTEM_KEYMASTER_WRAPPED_KEY_H_
