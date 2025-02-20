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

#include <keymaster/serializable.h>

#include <assert.h>

#include <keymaster/android_keymaster_utils.h>

namespace keymaster {

bool __buffer_bound_check(const uint8_t* buf, const uint8_t* end, size_t len) {
    uintptr_t buf_next;
    bool overflow_occurred = __builtin_add_overflow(__pval(buf), len, &buf_next);
    return (!overflow_occurred) && (buf_next <= __pval(end));
}

uint8_t* append_to_buf(uint8_t* buf, const uint8_t* end, const void* data, size_t data_len) {
    if (data != nullptr && __buffer_bound_check(buf, end, data_len)) {
        memcpy(buf, data, data_len);
        return buf + data_len;
    } else {
        return buf;
    }
}

bool copy_from_buf(const uint8_t** buf_ptr, const uint8_t* end, void* dest, size_t size) {
    if (__buffer_bound_check(*buf_ptr, end, size)) {
        memcpy(dest, *buf_ptr, size);
        *buf_ptr += size;
        return true;
    } else {
        return false;
    }
}

bool copy_size_and_data_from_buf(const uint8_t** buf_ptr, const uint8_t* end, size_t* size,
                                 UniquePtr<uint8_t[]>* dest) {
    if (!copy_uint32_from_buf(buf_ptr, end, size)) return false;

    if (*size == 0) {
        dest->reset();
        return true;
    }

    if (__buffer_bound_check(*buf_ptr, end, *size)) {
        dest->reset(new (std::nothrow) uint8_t[*size]);
        if (!dest->get()) {
            return false;
        }
        return copy_from_buf(buf_ptr, end, dest->get(), *size);
    } else {
        return false;
    }
}

bool Buffer::reserve(size_t size) {
    if (available_write() < size) {
        if (!valid_buffer_state()) {
            return false;
        }

        size_t new_size = buffer_size_ + size - available_write();
        uint8_t* new_buffer = new (std::nothrow) uint8_t[new_size];
        if (!new_buffer) return false;
        if (buffer_.get() != nullptr) {
            memcpy(new_buffer, buffer_.get() + read_position_, available_read());
            memset_s(buffer_.get(), 0, buffer_size_);
        }
        buffer_.reset(new_buffer);
        buffer_size_ = new_size;
        write_position_ -= read_position_;
        read_position_ = 0;
    }
    return true;
}

bool Buffer::Reinitialize(size_t size) {
    Clear();
    buffer_.reset(new (std::nothrow) uint8_t[size]);
    if (!buffer_.get()) return false;
    buffer_size_ = size;
    read_position_ = 0;
    write_position_ = 0;
    return true;
}

bool Buffer::Reinitialize(const void* data, size_t data_len) {
    Clear();
    if (__pval(data) + data_len < __pval(data))  // Pointer wrap check
        return false;
    buffer_.reset(new (std::nothrow) uint8_t[data_len]);
    if (!buffer_.get()) return false;
    buffer_size_ = data_len;
    if (data != nullptr) {
        memcpy(buffer_.get(), data, data_len);
    }
    read_position_ = 0;
    write_position_ = buffer_size_;
    return true;
}

size_t Buffer::available_write() const {
    assert(buffer_size_ >= write_position_);
    return buffer_size_ - write_position_;
}

size_t Buffer::available_read() const {
    assert(buffer_size_ >= write_position_);
    assert(write_position_ >= read_position_);
    return write_position_ - read_position_;
}

bool Buffer::valid_buffer_state() const {
    return (buffer_size_ >= write_position_) && (write_position_ >= read_position_);
}

bool Buffer::write(const uint8_t* src, size_t write_length) {
    if (available_write() < write_length) return false;
    memcpy(buffer_.get() + write_position_, src, write_length);
    write_position_ += write_length;
    return true;
}

bool Buffer::read(uint8_t* dest, size_t read_length) {
    if (available_read() < read_length) return false;
    memcpy(dest, buffer_.get() + read_position_, read_length);
    read_position_ += read_length;
    return true;
}

bool Buffer::advance_write(int distance) {
    if (distance < 0) {
        return false;
    }

    const size_t validated_distance = static_cast<size_t>(distance);
    size_t new_write_position = 0;

    // if an integer overflow occurred or the new position exceeds the buffer_size return false.
    if (__builtin_add_overflow(write_position_, validated_distance, &new_write_position) ||
        new_write_position > buffer_size_) {
        return false;
    }

    write_position_ = new_write_position;
    return true;
}

size_t Buffer::SerializedSize() const {
    return sizeof(uint32_t) + available_read();
}

uint8_t* Buffer::Serialize(uint8_t* buf, const uint8_t* end) const {
    return append_size_and_data_to_buf(buf, end, peek_read(), available_read());
}

bool Buffer::Deserialize(const uint8_t** buf_ptr, const uint8_t* end) {
    Clear();
    if (!copy_size_and_data_from_buf(buf_ptr, end, &buffer_size_, &buffer_)) {
        buffer_.reset();
        buffer_size_ = 0;
        return false;
    }
    write_position_ = buffer_size_;
    return true;
}

void Buffer::Clear() {
    memset_s(buffer_.get(), 0, buffer_size_);
    buffer_.reset();
    read_position_ = 0;
    write_position_ = 0;
    buffer_size_ = 0;
}

}  // namespace keymaster
