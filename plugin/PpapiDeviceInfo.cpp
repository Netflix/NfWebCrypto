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
,   isInited_(false)
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
}

void PpapiDeviceInfo::gotDeviceId(int32_t result, const pp::Var& deviceId)
{
    assert(isMainThread());
    ScopedMutex scopedMutex(mutex_);
    rawDeviceIdStr_.clear();
    if (result == PP_OK && deviceId.is_string())
        rawDeviceIdStr_ = deviceId.AsString();
    // Google says the device ID from PPAPI will always be 64 chars: a string
    // with the text value of the numerical ID.
    const string::size_type SPEC_SIZE = 64;
    string::size_type rawSize = rawDeviceIdStr_.size();
    // If the actual size is out of spec, at least make sure the size is capped
    // at 64 and even.
    if (rawSize > SPEC_SIZE)
        rawDeviceIdStr_.resize(SPEC_SIZE);
    else if (rawSize % 2)
        rawDeviceIdStr_.resize(rawSize-1);
    isInited_ = true;
    condVar_.signal();
}

void PpapiDeviceInfo::waitUntilReady()
{
    assert(!isMainThread());
    // We get initialized by the PPAPI callback requested in the ctor. Block
    // here until that happens. Once the callback occurs, or we time out waiting
    // for it, we are forever after initialized.
    ScopedMutex scopedMutex(mutex_);
    if (!isInited_)
    {
        static const uint64_t timeoutMs(2000);    // 2s timeout
        ConditionVariable::Error err = ConditionVariable::OK;
        while (!isInited_)
        {
            err = condVar_.wait(mutex_, timeoutMs);
            if (err != ConditionVariable::OK)
                break;
        }
        if (err != ConditionVariable::OK)
        {
            DLOG() << "PpapiDeviceInfo::getDeviceId: timeout or other error waiting for mainthread callback\n";
            rawDeviceIdStr_.clear();
        }
        isInited_ = true;
    }
}

vector<uint8_t> PpapiDeviceInfo::getBinaryDeviceId()
{
    // Block until the mainthread callback has populated rawDeviceIdStr_
    waitUntilReady();
    if (deviceIdBin_.empty())
    {
        // For devices that don't support device ID, return all zeros
        if (rawDeviceIdStr_.empty())
        {
            deviceIdBin_ = vector<unsigned char>(32, 0);
        }
        else
        {
            deviceIdBin_ = hexTextToBin(rawDeviceIdStr_);
            // deviceIdBin_ should be 32 bytes by spec. If not pad with zeros.
            if (deviceIdBin_.size() != 32)
            {
                const vector<unsigned char> zeros(32 - deviceIdBin_.size(), 0);
                std::copy(zeros.begin(), zeros.end(), back_inserter(deviceIdBin_));
            }
        }
    }
    return deviceIdBin_;
}

string PpapiDeviceInfo::getDeviceId()
{
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
