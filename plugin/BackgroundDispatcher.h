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
#ifndef BACKGROUNDDISPATCHER_H_
#define BACKGROUNDDISPATCHER_H_
#include <string>
#include <queue>
#include <base/Mutex.h>
#include <base/SimpleThread.h>
#include <base/ConditionVariable.h>

namespace cadmium
{

class INativeBridge;

class BackgroundDispatcher : public base::SimpleThread
{
public:
    BackgroundDispatcher(INativeBridge * nativeBridge);
    virtual ~BackgroundDispatcher();
    bool postMessage(const std::string& message);
    virtual void threadFunc();
private:
    INativeBridge * const nativeBridge_;
    bool isRunning_;
    base::Mutex mutex_;
    base::ConditionVariable condVar_;
    std::queue<std::string> msgFifo_;
};

}   // namespace cadmium

#endif /* BACKGROUNDDISPATCHER_H_ */
