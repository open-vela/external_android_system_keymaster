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

#ifndef KEYMASTER_OPENSSL_ERR_H
#define KEYMASTER_OPENSSL_ERR_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ERR_GET_LIB(l) (int)(((l) >> 24L) & 0x0FFL)
#define ERR_GET_REASON(l) (int)((l)&0xFFFL)
#define ERR_LIB_CIPHER 30

unsigned long ERR_peek_last_error(void);
void ERR_error_string_n(unsigned long e, char* buf, size_t len);

#ifdef __cplusplus
}
#endif
#endif  // KEYMASTER_OPENSSL_ERR_H