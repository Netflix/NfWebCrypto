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
#include "Key.h"

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
        const std::vector<KeyUsage>& keyUsage, uint32_t& keyHandle);
    CadErr exportKey(uint32_t keyHandle, KeyFormat format, std::string& keyData);
    CadErr getKeyInfo(uint32_t keyHandle, KeyType& type, bool& extractable,
            base::Variant& algVar, std::vector<KeyUsage>& usage) const;
    CadErr aesCbc(uint32_t keyHandle, const std::string& ivIn,
            const std::string& dataIn, CipherOp cipherOp, std::string& dataOut);
    CadErr aesGcm(uint32_t keyHandle, const std::string& ivIn, const std::string& dataIn,
            const std::string& aadIn, uint8_t taglenBits, CipherOp cipherOp,
            std::string& dataOut);
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
    CadErr pbkdf2Derive(const std::string& salt, uint32_t iterations,
            const base::Variant& prf, const std::string& password,
            const base::Variant& derivedAlgObj, bool extractable,
            const std::vector<KeyUsage> usage, uint32_t &keyHandle);
    CadErr getKeyByName(const std::string keyName, uint32_t &keyHandle, std::string& metadata);
    CadErr getDeviceId(std::string& deviceId) const;
    CadErr getSystemKeyHandle(uint32_t& systemKeyHandle) const;
private:
    void importPreSharedKeys();
    uint32_t importNamedKey(const NamedKey& nk);
    bool hasKey(uint32_t keyHandle) const;
    bool isUsageAllowed(uint32_t keyHandle, KeyUsage keyUsage);
    bool isKeyAlgMatch(uint32_t keyHandle, Algorithm algorithm);
    void createSystemKey();
    CadErr importKeyInternal(KeyFormat format, const std::string& keyData,
        const base::Variant& algVar, bool extractable,
        const std::vector<KeyUsage>& keyUsage, uint32_t& keyHandle);
    CadErr importJwk(const Vuc& keyVuc, const base::Variant& algVar, bool extractable,
        const std::vector<KeyUsage>& keyUsage, uint32_t& keyHandle);
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
    struct NamedKeySpec
    {
        const uint32_t keyHandle;
        const std::string id;
        NamedKeySpec(uint32_t kh, const std::string& id) : keyHandle(kh), id(id) {}
    };
    typedef std::map<std::string, NamedKeySpec> NamedKeyMap;
    NamedKeyMap namedKeyMap_;
};

}}   // namespace cadmium::crypto

#endif /* CADMIUMCRYPTOIMPL_H_ */
