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
#ifndef NATIVEBRIDGE_H_
#define NATIVEBRIDGE_H_
#include <stdint.h>
#include <ppapi/utility/completion_callback_factory.h>
#include <base/Noncopyable.h>
#include <base/Variant.h>
#include <crypto/CadmiumCrypto.h>
#include "INativeBridge.h"

namespace pp {class InstancePrivate;}

namespace cadmium
{

class NativeBridge : public INativeBridge, private base::Noncopyable
{
public:
    NativeBridge(pp::InstancePrivate * pInstance, crypto::CadmiumCrypto * cadmiumCrypto);
    virtual ~NativeBridge();
    virtual void handleMessage(const std::string& message);
    virtual void postMessage(const std::string& message);
    virtual void sendReady(int errCode);
private:
    void invoke(const base::Variant& request);
    bool isError(uint32_t errCode, const std::string& cmdIndex);
    void sendError(const std::string& index, uint32_t errCode);
    void send(const base::Variant& data);
    void postMessageCb(int32_t /*result*/, const std::string& json);
    template <typename T>
    bool getVal(const base::Variant& args, const char * varName,
            const std::string& cmdIndex, T& out, bool doSendErr = true);
    bool keyHandleToKeyVarMap(uint32_t keyHandle, base::VariantMap& keyVarMap);
    bool doSign(const std::string& cmdIndex, int keyHandle,
            crypto::CadmiumCrypto::Algorithm algType, crypto::CadmiumCrypto::Algorithm hashType,
            const std::string& dataStr64, base::VariantMap& returnVarMap);
    bool doVerify(const std::string& cmdIndex, int keyHandle,
            crypto::CadmiumCrypto::Algorithm algType, crypto::CadmiumCrypto::Algorithm hashType,
            const std::string& dataStr64, const std::string& sigStr64,
            base::VariantMap& returnVarMap);
    typedef bool (JsMethod)(const std::string& cmdIdx, base::Variant& argsVar,
            base::VariantMap& returnVarMap);
    JsMethod digest;
    JsMethod importKey;
    JsMethod exportKey;
    JsMethod encrypt;
    JsMethod decrypt;
    JsMethod sign;
    JsMethod verify;
    JsMethod generate;
    JsMethod derive;
    JsMethod addEntropy;
    JsMethod unwrapKey;
    JsMethod wrapKey;
    JsMethod encryptDecrypt;
    JsMethod signVerify;
    JsMethod getDeviceId;
    JsMethod getKeyByName;
private:
    pp::InstancePrivate * const pInstance_;
    crypto::CadmiumCrypto * const cadmiumCrypto_;
    pp::CompletionCallbackFactory<NativeBridge> callbackFactory_;
    typedef bool (NativeBridge::*JsMethodPtr)(const std::string& cmdIdx,
            base::Variant& argsVar, base::VariantMap& returnVarMap);
    typedef std::map<std::string, JsMethodPtr> JsFunctionMap;
    JsFunctionMap jsFunctionMap_;
};

} // namespace cadmium

#endif /* NATIVEBRIDGE_H_ */
