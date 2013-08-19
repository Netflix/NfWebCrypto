/*
 * (c) 2012 Netflix, Inc.  All content herein is protected by U.S. copyright and
 * other applicable intellectual property laws and may not be copied without the
 * express permission of Netflix, Inc., which reserves all rights.  Reuse of any
 * of this content for any purpose without the permission of Netflix, Inc. is
 * strictly prohibited.
 */
#include "PpapiDeviceInfo.h"
#include <stdlib.h>
#include <string>
#include <algorithm>
#include <ppapi/cpp/var.h>
#include <ppapi/cpp/private/flash_device_id.h>
#include <base/ScopedMutex.h>
#include <base/DebugUtil.h>
#include "MainThreadUtil.h"
#include "Base32.h"

using namespace std;
using cadmium::base::ScopedMutex;

namespace cadmium
{

namespace
{

vector<unsigned char> hexTextToBin(const string& hexText)
{
    // Since hexText is a hex number in a text string, each two chars represent
    // an 8-bit number.
    assert((hexText.size() % 2) == 0);
    vector<uint8_t> data;
    data.reserve(hexText.size()/2);
    string::size_type idx = 0;
    while (idx < hexText.size())
    {
        const string byteHex = hexText.substr(idx, 2);
        const unsigned char byteBin = static_cast<unsigned char>(strtol(byteHex.c_str(), NULL, 16));
        data.push_back(byteBin);
        idx += 2;
    }
    return data;
}

}   // anonymous namespace

PpapiDeviceInfo::PpapiDeviceInfo(pp::InstancePrivate* pInstance)
:   callbackFactory_(this)
,   ppDeviceId_(new pp::flash::DeviceID(pInstance))
{
    assert(isMainThread());
    originStr_ =
        pInstance->GetWindowObject().GetProperty("top").GetProperty("location").GetProperty("host").AsString();
    pp::CompletionCallbackWithOutput<pp::Var> cb =
         callbackFactory_.NewCallbackWithOutput(&PpapiDeviceInfo::gotDeviceId);
    int32_t result = ppDeviceId_->GetDeviceID(cb);
    if (result != PP_OK_COMPLETIONPENDING)
        cb.Run(result);
}

PpapiDeviceInfo::~PpapiDeviceInfo()
{
    condVar_.signal();
}

void PpapiDeviceInfo::gotDeviceId(int32_t result, const pp::Var& deviceId)
{
    assert(isMainThread());
    ScopedMutex scopedMutex(mutex_);
    string rawDeviceIdStr;
    if (result == PP_OK && deviceId.is_string())
        rawDeviceIdStr = deviceId.AsString();
    // Google says the device ID from PPAPI, when supported, will always be 64
    // chars: a string with the text value of the numerical ID. Clamp or extend
    // the actual received value to this length.
    const string::size_type SPEC_SIZE = 64;
    rawDeviceIdStr.resize(SPEC_SIZE, '0');
    // Now convert the text numerical ID to a binary value
    deviceIdBin_ = hexTextToBin(rawDeviceIdStr);
    assert(deviceIdBin_.size() == 32);
    // We are now initialized
    condVar_.signal();
}

vector<uint8_t> PpapiDeviceInfo::getBinaryDeviceId()
{
    assert(!isMainThread());
    // We get initialized by the PPAPI callback requested in the ctor. Block
    // here until that happens. Once the callback occurs, or we time out waiting
    // for it, we are forever after initialized.
    ScopedMutex scopedMutex(mutex_);
    if (deviceIdBin_.empty())
    {
        static const uint64_t timeoutMs(8000);    // 8s timeout
        ConditionVariable::Error err = ConditionVariable::OK;
        while (deviceIdBin_.empty())
        {
            err = condVar_.wait(mutex_, timeoutMs);
            if (err != ConditionVariable::OK)
                break;
        }
    }
    return deviceIdBin_;
}

string PpapiDeviceInfo::getDeviceId()
{
    assert(!isMainThread());
    if (deviceIdStr_.empty())
    {
        vector<uint8_t> binId = getBinaryDeviceId();
        // Convert the vector of 32 8-bit values to Base32, and this becomes a
        // 52-byte ESN-compatible device ID.
        if (!binId.empty())
            deviceIdStr_ = Base32::encode(binId);
    }
    return deviceIdStr_;
}

}   // namespace cadmium
