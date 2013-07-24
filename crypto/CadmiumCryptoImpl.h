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
#ifndef CADMIUMCRYPTOIMPL_H_
#define CADMIUMCRYPTOIMPL_H_

#include "CadmiumCrypto.h"
#include <tr1/memory>
#include <map>
#include <base/Variant.h>
#include <base/Noncopyable.h>

namespace cadmium {
namespace crypto {

class RsaContext;
class DiffieHellmanContext;

class CadmiumCrypto::CadmiumCryptoImpl : base::Noncopyable
{
public:
    CadmiumCryptoImpl(IDeviceInfo * pDeviceInfo);
    ~CadmiumCryptoImpl();
    CadErr init(const Vuc& prngSeed);
    void addEntropy(const std::string& entropyBytes);
    CadErr digest(Algorithm algorithm, const std::string& data, std::string& digest);
    CadErr importKey(KeyFormat format, const std::string& keyData,
        const base::Variant& algVar, bool extractable,
        const std::vector<KeyUsage>& keyUsage, uint32_t& keyHandle, KeyType& keyType);
    CadErr exportKey(uint32_t keyHandle, KeyFormat format, std::string& keyData);
    CadErr getKeyInfo(uint32_t keyHandle, KeyType& type, bool& extractable,
            base::Variant& algVar, std::vector<KeyUsage>& usage) const;
    CadErr aesCbc(uint32_t keyHandle, const std::string& ivIn,
            const std::string& dataIn, CipherOp cipherOp, std::string& dataOut);
    CadErr aesGcmEncrypt(uint32_t keyHandle, const std::string& ivIn,
            const std::string& dataIn, const std::string& aadIn,
            std::string& tagOut, std::string& dataOut);
    CadErr aesGcmDecrypt(uint32_t keyHandle, const std::string& ivIn,
            const std::string& dataIn, const std::string& aadIn,
            const std::string& tagIn, std::string& dataOut);
    CadErr rsaCrypt(uint32_t keyHandle, const std::string& dataIn,
            CipherOp cipherOp, std::string& dataOut);
    CadErr hmac(uint32_t keyHandle, Algorithm shaAlgo, KeyUsage opUsage,
            const std::string& data, std::string& hmac);
    CadErr rsaKeyGen(const base::Variant& algVar, bool extractable,
            std::vector<KeyUsage> keyUsage, uint32_t& pubKeyHandle,
            uint32_t& privKeyHandle);
    CadErr rsaSign(uint32_t keyHandle, Algorithm shaAlgo, const std::string& data,
            std::string& sig);
    CadErr rsaVerify(uint32_t keyHandle, Algorithm shaAlgo, const std::string& data,
            const std::string& sig, bool& isVerified);
    CadErr dhKeyGen(const base::Variant& algVar, bool extractable,
            std::vector<KeyUsage> keyUsage, uint32_t& pubKeyHandle,
            uint32_t& privKeyHandle);
    CadErr dhDerive(uint32_t baseKeyHandle, const std::string& peerPublicKeyData,
            const base::Variant& derivedAlgObj, bool extractable,
            std::vector<KeyUsage> keyUsage, uint32_t& keyHandle);
    CadErr unwrapJwe(const std::string& jweData, uint32_t wrappingKeyHandle,
            const base::Variant& algVar, bool extractable,
            const std::vector<KeyUsage>& keyUsage, uint32_t& keyHandle);
    CadErr wrapJwe(uint32_t toBeWrappedKeyHandle, uint32_t wrappingKeyHandle,
            const base::Variant& wrappingAlgoObj, JweEncMethod jweEncMethod,
            std::string& wrappedKeyJcs);
    CadErr symKeyGen(const base::Variant& algVar, bool extractable,
            const std::vector<KeyUsage> keyUsage, uint32_t &keyHandle);
    CadErr getDeviceId(std::string& deviceId) const;
    CadErr getSystemKeyHandle(uint32_t& systemKeyHandle) const;
private:
    struct Key
    {
        std::vector<unsigned char> key;
        std::tr1::shared_ptr<RsaContext> pRsaContext;
        std::tr1::shared_ptr<DiffieHellmanContext> pDhContext;
        KeyType type;
        bool extractable;
        base::Variant algVar;
        std::vector<KeyUsage> keyUsage;
        Key();
        Key(const std::vector<unsigned char>& key, std::tr1::shared_ptr<RsaContext> pRsaContext,
            KeyType kt, bool extractable, const base::Variant& algVar, const std::vector<KeyUsage>& usg);
        Key(const std::vector<unsigned char>& key, std::tr1::shared_ptr<DiffieHellmanContext> pDhContext,
            KeyType kt, bool extractable, const base::Variant& algVar, const std::vector<KeyUsage>& usg);
        Key(const Key& rhs);
        Key& operator=(const Key& rhs);
    };
private:
    bool hasKey(uint32_t keyHandle) const;
    bool isUsageAllowed(uint32_t keyHandle, KeyUsage keyUsage);
    bool isKeyAlgMatch(uint32_t keyHandle, Algorithm algorithm);
    void createSystemKey();
    CadErr importJwk(const Vuc& keyVuc, const base::Variant& algVar, bool extractable,
        const std::vector<KeyUsage>& keyUsage, uint32_t& keyHandle, KeyType& keyType);
    CadErr exportJwk(const Key& key, std::string& keyData);
    CadErr unwrapJwe(const std::vector<std::string>& jweData, uint32_t wrappingKeyHandle,
            const base::Variant& algVar, bool extractable,
            const std::vector<KeyUsage>& keyUsage, uint32_t& keyHandle);
    CadErr aesPre(uint32_t keyHandle, KeyUsage keyUsage, const std::string& ivInStr64,
            const std::string& dataInStr64, Algorithm algorithm, Vuc& ivVec,
            Vuc& dataVec, Vuc& keyVec);
private:
    IDeviceInfo * const pDeviceInfo_;
    bool isInited_;
    std::map<uint32_t, std::vector<unsigned char> > keyCache_;
    uint32_t nextKeyHandle_;
    std::map<uint32_t, Key> keyMap_;
    uint32_t systemKeyHandle_;
};

}}   // namespace cadmium::crypto

#endif /* CADMIUMCRYPTOIMPL_H_ */
