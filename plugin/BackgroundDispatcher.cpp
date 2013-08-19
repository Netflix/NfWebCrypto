/*
 *
 *  Copyright 2013 Netflix, Inc.
 *
 *     Licensed under the Apache License, Version 2.0 (the "License");
 *     you may not use this file except in compliance with the License.
 *     You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 *     Unless required by applicable law or agreed to in writing, software
 *     distributed under the License is distributed on an "AS IS" BASIS,
 *     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *     See the License for the specific language governing permissions and
 *     limitations under the License.
 *
 */
#include "BackgroundDispatcher.h"
#include <assert.h>
#include <base/ScopedMutex.h>
#include <base/Variant.h>
#include <base/DebugUtil.h>
#include "INativeBridge.h"
#include "MainThreadUtil.h"

using namespace std;
using namespace cadmium::base;

namespace   // anonymous
{

const char * const STOPMESSAGE = "JaneStopThisCrazyThing";

}   // namespace anonymous

namespace cadmium
{

BackgroundDispatcher::BackgroundDispatcher(INativeBridge * nativeBridge)
:   nativeBridge_(nativeBridge)
,   isRunning_(false)
{
    FUNCTIONSCOPELOG;
    assert(nativeBridge_);
}

BackgroundDispatcher::~BackgroundDispatcher()
{
    FUNCTIONSCOPELOG;
    assert(isMainThread());
    postMessage(STOPMESSAGE);
    join();
}

bool BackgroundDispatcher::postMessage(const string& message)
{
    FUNCTIONSCOPELOG;
    assert(isMainThread());
    ScopedMutex scopedMutex(mutex_);
    msgFifo_.push(message);
    condVar_.signal();
    return true;
}

void BackgroundDispatcher::threadFunc()
{
    FUNCTIONSCOPELOG;
    assert(!isMainThread());
    isRunning_ = true;
    while (isRunning_)
    {
        while (msgFifo_.empty())
        {
            ScopedMutex scopedMutex(mutex_);
            ConditionVariable::Error err = condVar_.wait(mutex_);
            assert(err == ConditionVariable::OK); (void)err;
        }
        assert(!msgFifo_.empty());
        string message;
        {
            ScopedMutex scopedMutex(mutex_);
            message = msgFifo_.front();
            assert(!message.empty());
            msgFifo_.pop();
        }
        if (message == STOPMESSAGE)
        {
            isRunning_ = false;
            continue;
        }
        nativeBridge_->handleMessage(message);
    }
}

}   // namespace cadmium
