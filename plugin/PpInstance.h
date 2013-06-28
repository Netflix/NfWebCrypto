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
#ifndef PPINSTANCE_H_
#define PPINSTANCE_H_
#include <stdint.h>
#include <memory>
#include <ppapi/cpp/private/instance_private.h>
#include <ppapi/utility/completion_callback_factory.h>

namespace cadmium
{

class BackgroundDispatcher;
class INativeBridge;
class IDeviceInfo;

namespace base { class SimpleThread; }

namespace crypto { class CadmiumCrypto; }

class PpInstance : public pp::InstancePrivate
{
public:
    explicit PpInstance(PP_Instance instance);
    virtual ~PpInstance();
    virtual bool Init(uint32_t argc, const char* argn[], const char* argv[]);
    virtual void HandleMessage(const pp::Var& message);
private:
    uint32_t initOnBackgroundThread(uint32_t);
    bool checkUsedInterfaces();
    void handleOptions(uint32_t argc, const char* argn[], const char* argv[]);
private:
    pp::CompletionCallbackFactory<PpInstance> callbackFactory_;
    base::SimpleThread * backgroundInitThread_;
    BackgroundDispatcher * backgroundDispatcher_;
    std::auto_ptr<cadmium::INativeBridge> nativeBridge_;
    std::auto_ptr<cadmium::crypto::CadmiumCrypto> cadmiumCrypto_;
    uint32_t msgCount_;
    std::vector<unsigned char> randSeed_;
    std::auto_ptr<IDeviceInfo> deviceInfo_;
};

}   // namespace cadmium


#endif // PPINSTANCE_H_
