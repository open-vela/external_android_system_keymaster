/*
 * Copyright (C) 2016 The Android Open Source Project
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

#include <keymaster/keymaster_configuration.h>

#include <regex>
#include <string>

#include <regex.h>

#define LOG_TAG "keymaster"

#include <android-base/logging.h>
#include <android-base/properties.h>
#include <log/log.h>

#include <keymaster/authorization_set.h>

namespace keymaster {

namespace {

constexpr char kPlatformVersionProp[] = "ro.build.version.release";
constexpr char kPlatformVersionRegex[] = "^([0-9]{1,2})(\\.([0-9]{1,2}))?(\\.([0-9]{1,2}))?";
constexpr size_t kMajorVersionMatch = 1;
constexpr size_t kMinorVersionMatch = 3;
constexpr size_t kSubminorVersionMatch = 5;
constexpr size_t kPlatformVersionMatchCount = kSubminorVersionMatch + 1;

constexpr char kPlatformPatchlevelProp[] = "ro.build.version.security_patch";
constexpr char kVendorPatchlevelProp[] = "ro.vendor.build.security_patch";
constexpr char kPatchlevelRegex[] = "^([0-9]{4})-([0-9]{2})-([0-9]{2})$";
constexpr char kVerifiedBootStateProp[] = "ro.boot.verifiedbootstate";
constexpr char kVbmetaDeviceStateProp[] = "ro.boot.vbmeta.device_state";
constexpr char kVbmetaDigestProp[] = "ro.boot.vbmeta.digest";
constexpr size_t kYearMatch = 1;
constexpr size_t kMonthMatch = 2;
constexpr size_t kDayMatch = 3;
constexpr size_t kPatchlevelMatchCount = kDayMatch + 1;

uint32_t match_to_uint32(const char* expression, const regmatch_t& match) {
    if (match.rm_so == -1) return 0;

    size_t len = match.rm_eo - match.rm_so;
    std::string s(expression + match.rm_so, len);
    return std::stoul(s);
}

std::string wait_and_get_property(const char* prop) {
    std::string prop_value;
#ifndef KEYMASTER_UNIT_TEST_BUILD
    while (!android::base::WaitForPropertyCreation(prop)) {
        SLOGE("waited 15s for %s, still waiting...", prop);
    }
    prop_value = android::base::GetProperty(prop, "" /* default */);
#endif
    return prop_value;
}

enum class PatchlevelOutput { kYearMonthDay, kYearMonth };

uint32_t GetPatchlevel(const char* patchlevel_str, PatchlevelOutput detail) {
    regex_t regex;
    if (regcomp(&regex, kPatchlevelRegex, REG_EXTENDED) != 0) {
        ALOGE("Failed to compile platform patchlevel regex! (%s)", kPatchlevelRegex);
        return 0;
    }

    regmatch_t matches[kPatchlevelMatchCount];
    int not_match = regexec(&regex, patchlevel_str, kPatchlevelMatchCount, matches, 0 /* flags */);
    regfree(&regex);
    if (not_match) {
        ALOGI(" patchlevel string does not match expected format.  Using patchlevel 0");
        return 0;
    }

    uint32_t year = match_to_uint32(patchlevel_str, matches[kYearMatch]);
    uint32_t month = match_to_uint32(patchlevel_str, matches[kMonthMatch]);

    if (month < 1 || month > 12) {
        ALOGE("Invalid patch month %" PRIu32, month);
        return 0;
    }

    switch (detail) {
    case PatchlevelOutput::kYearMonthDay: {
        uint32_t day = match_to_uint32(patchlevel_str, matches[kDayMatch]);
        if (day < 1 || day > 31) {
            ALOGE("Invalid patch day %" PRIu32, day);
            return 0;
        }
        return year * 10000 + month * 100 + day;
    }
    case PatchlevelOutput::kYearMonth:
        return year * 100 + month;
    }
    return 0;
}

}  // anonymous namespace

keymaster_error_t ConfigureDevice(keymaster2_device_t* dev, uint32_t os_version,
                                  uint32_t os_patchlevel) {
    AuthorizationSet config_params(AuthorizationSetBuilder()
                                       .Authorization(keymaster::TAG_OS_VERSION, os_version)
                                       .Authorization(keymaster::TAG_OS_PATCHLEVEL, os_patchlevel));
    return dev->configure(dev, &config_params);
}

keymaster_error_t ConfigureDevice(keymaster2_device_t* dev) {
    return ConfigureDevice(dev, GetOsVersion(), GetOsPatchlevel());
}

uint32_t GetOsVersion(const char* version_str) {
    regex_t regex;
    if (regcomp(&regex, kPlatformVersionRegex, REG_EXTENDED)) {
        ALOGE("Failed to compile version regex! (%s)", kPlatformVersionRegex);
        return 0;
    }

    regmatch_t matches[kPlatformVersionMatchCount];
    int not_match =
        regexec(&regex, version_str, kPlatformVersionMatchCount, matches, 0 /* flags */);
    regfree(&regex);
    if (not_match) {
        ALOGI("Platform version string \"%s\" does not match expected format.  Using version 0.",
              version_str);
        return 0;
    }

    uint32_t major = match_to_uint32(version_str, matches[kMajorVersionMatch]);
    uint32_t minor = match_to_uint32(version_str, matches[kMinorVersionMatch]);
    uint32_t subminor = match_to_uint32(version_str, matches[kSubminorVersionMatch]);

    return (major * 100 + minor) * 100 + subminor;
}

uint32_t GetOsVersion() {
    std::string version = wait_and_get_property(kPlatformVersionProp);
    return GetOsVersion(version.c_str());
}

uint32_t GetOsPatchlevel(const char* patchlevel_str) {
    return GetPatchlevel(patchlevel_str, PatchlevelOutput::kYearMonth);
}

uint32_t GetOsPatchlevel() {
    std::string patchlevel = wait_and_get_property(kPlatformPatchlevelProp);
    return GetOsPatchlevel(patchlevel.c_str());
}

uint32_t GetVendorPatchlevel() {
    std::string patchlevel = wait_and_get_property(kVendorPatchlevelProp);
    return GetPatchlevel(patchlevel.c_str(), PatchlevelOutput::kYearMonthDay);
}

std::string GetVerifiedBootState() {
    // Do not wait for bootloader-set properties. They are passed to the kernel
    // on the command line, and should always be available. If not available at
    // this point, it will never be available.
    return android::base::GetProperty(kVerifiedBootStateProp, /*default_value=*/"red");
}

std::string GetBootloaderState() {
    // Do not wait for bootloader-set properties. They are passed to the kernel
    // on the command line, and should always be available. If not available at
    // this point, it will never be available.
    return android::base::GetProperty(kVbmetaDeviceStateProp, /*default_value=*/"unlocked");
}

std::optional<uint8_t> HexCharToInt(char c) {
    switch (c) {
    case '0':
        return 0x0;
    case '1':
        return 0x1;
    case '2':
        return 0x2;
    case '3':
        return 0x3;
    case '4':
        return 0x4;
    case '5':
        return 0x5;
    case '6':
        return 0x6;
    case '7':
        return 0x7;
    case '8':
        return 0x8;
    case '9':
        return 0x9;
    case 'a':
        return 0xa;
    case 'A':
        return 0xa;
    case 'b':
        return 0xb;
    case 'B':
        return 0xb;
    case 'c':
        return 0xc;
    case 'C':
        return 0xc;
    case 'd':
        return 0xd;
    case 'D':
        return 0xd;
    case 'e':
        return 0xe;
    case 'E':
        return 0xe;
    case 'f':
        return 0xf;
    case 'F':
        return 0xf;
    default:
        return std::nullopt;
    }
}

std::optional<std::vector<uint8_t>> GetVbmetaDigest(std::string_view vbmeta_string) {
    if (vbmeta_string.size() % 2 == 1) {
        LOG(ERROR) << "hex string has an odd length (" << vbmeta_string.size() << ")";
        return std::nullopt;
    }

    std::vector<uint8_t> out;
    out.reserve(vbmeta_string.size() / 2);
    for (auto next = vbmeta_string.begin(); next != vbmeta_string.end(); next += 2) {
        auto high_nibble = HexCharToInt(*next);
        auto low_nibble = HexCharToInt(*(next + 1));
        if (!high_nibble || !low_nibble) {
            LOG(ERROR) << "invalid input: '" << *next << "' or '" << *(next + 1) << "'";
            return std::nullopt;
        }
        out.push_back((*high_nibble << 4) | *low_nibble);
    }

    return out;
}

std::optional<std::vector<uint8_t>> GetVbmetaDigest() {
    // Do not wait for bootloader-set properties. They are passed to the kernel
    // on the command line, and should always be available. If not available at
    // this point, it will never be available.
    auto vbmeta_string = android::base::GetProperty(
        kVbmetaDigestProp,
        /*default_value=*/"0000000000000000000000000000000000000000000000000000000000000000");
    return GetVbmetaDigest(vbmeta_string);
}

}  // namespace keymaster
