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
#include "CadmiumCrypto.h"
#include <assert.h>
#include "CadmiumCryptoImpl.h"

using namespace std;

namespace cadmium {

using namespace base;

namespace crypto {

namespace //anonymous
{

map<string, CadmiumCrypto::Algorithm> gStr2AlgTab;
void initStr2AlgTab()
{
    gStr2AlgTab["HMAC"]              = CadmiumCrypto::HMAC;
    gStr2AlgTab["AES-CBC"]           = CadmiumCrypto::AES_CBC;
    gStr2AlgTab["AES-CTR"]           = CadmiumCrypto::AES_CTR;
    gStr2AlgTab["AES-GCM"]           = CadmiumCrypto::AES_GCM;
    gStr2AlgTab["RSAES-PKCS1-v1_5"]  = CadmiumCrypto::RSAES_PKCS1_V1_5;
    gStr2AlgTab["RSASSA-PKCS1-v1_5"] = CadmiumCrypto::RSASSA_PKCS1_V1_5;
    gStr2AlgTab["RSA-OAEP"]          = CadmiumCrypto::RSA_OAEP;
    gStr2AlgTab["SHA-1"]             = CadmiumCrypto::SHA1;
    gStr2AlgTab["SHA-224"]           = CadmiumCrypto::SHA224;
    gStr2AlgTab["SHA-256"]           = CadmiumCrypto::SHA256;
    gStr2AlgTab["SHA-384"]           = CadmiumCrypto::SHA384;
    gStr2AlgTab["SHA-512"]           = CadmiumCrypto::SHA512;
    gStr2AlgTab["AES-KW"]            = CadmiumCrypto::AES_KW;
    gStr2AlgTab["DH"]                = CadmiumCrypto::DH;
    gStr2AlgTab["PBKDF2"]            = CadmiumCrypto::PBKDF2;
    gStr2AlgTab["SYSTEM"]            = CadmiumCrypto::SYSTEM;
}

}   // anonymous namespace

// CadmiumCrypto is "compiler firewall" in front of CadmiumCryptoImpl

CadmiumCrypto::CadmiumCrypto(IDeviceInfo * pDeviceInfo)
:   impl_(new CadmiumCryptoImpl(pDeviceInfo))
{
    initStr2AlgTab();
}

CadmiumCrypto::~CadmiumCrypto()
{
}

CadErr CadmiumCrypto::init(const Vuc& prngSeed)
{
    return impl_->init(prngSeed);
}

void CadmiumCrypto::addEntropy(const string& entropyBytes)
{
    impl_->addEntropy(entropyBytes);
}

CadErr CadmiumCrypto::digest(Algorithm algorithm, const string& data, string& digest)
{
    return impl_->digest(algorithm, data, digest);
}

CadErr CadmiumCrypto::importKey(KeyFormat format, const string& keyData,
    const Variant& algVar, bool extractable, const vector<KeyUsage>& keyUsage,
    uint32_t& keyHandle)
{
    return impl_->importKey(format, keyData, algVar, extractable, keyUsage,
            keyHandle);
}

CadErr CadmiumCrypto::exportKey(uint32_t keyHandle, KeyFormat format, string& keyData)
{
    return impl_->exportKey(keyHandle, format, keyData);
}

CadErr CadmiumCrypto::getKeyInfo(uint32_t keyHandle, KeyType& type, bool& extractable,
        Variant& algVar, vector<KeyUsage>& usage) const
{
    return impl_->getKeyInfo(keyHandle, type, extractable, algVar, usage);
}

CadErr CadmiumCrypto::symKeyGen(const Variant& algVar, bool extractable,
        const vector<KeyUsage> keyUsage, uint32_t &keyHandle)
{
    return impl_->symKeyGen(algVar, extractable, keyUsage, keyHandle);
}

CadErr CadmiumCrypto::aesCbc(uint32_t keyHandle, const string& ivIn,
        const string& dataIn, CipherOp cipherOp, string& dataOut)
{
    return impl_->aesCbc(keyHandle, ivIn, dataIn, cipherOp, dataOut);
}

CadErr CadmiumCrypto::aesGcm(uint32_t keyHandle, const string& ivIn, const string& dataIn,
        const string& aadIn, uint8_t taglen, CipherOp cipherOp, string& dataOut)
{
    return impl_->aesGcm(keyHandle, ivIn, dataIn, aadIn, taglen, cipherOp, dataOut);
}

CadErr CadmiumCrypto::rsaCrypt(uint32_t keyHandle, const string& dataIn,
        CipherOp cipherOp, string& dataOut)
{
    return impl_->rsaCrypt(keyHandle, dataIn, cipherOp, dataOut);
}

CadErr CadmiumCrypto::hmac(uint32_t keyHandle, Algorithm shaAlgo, KeyUsage opUsage,
        const string& data, string& hmac)
{
    return impl_->hmac(keyHandle, shaAlgo, opUsage, data, hmac);
}

CadErr CadmiumCrypto::rsaKeyGen(const Variant& algVar, bool extractable,
        vector<KeyUsage> keyUsage, uint32_t& pubKeyHandle, uint32_t& privKeyHandle)
{
    return impl_->rsaKeyGen(algVar, extractable, keyUsage, pubKeyHandle, privKeyHandle);
}

CadErr CadmiumCrypto::rsaSign(uint32_t keyHandle, Algorithm shaAlgo, const string& data,
        string& sig)
{
    return impl_->rsaSign(keyHandle, shaAlgo, data, sig);
}

CadErr CadmiumCrypto::rsaVerify(uint32_t keyHandle, Algorithm shaAlgo, const string& data,
        const string& sig, bool& isVerified)
{
    return impl_->rsaVerify(keyHandle, shaAlgo, data, sig, isVerified);
}

CadErr CadmiumCrypto::dhKeyGen(const Variant& algVar, bool extractable,
        vector<KeyUsage> keyUsage, uint32_t& pubKeyHandle, uint32_t& privKeyHandle)
{
    return impl_->dhKeyGen(algVar, extractable, keyUsage, pubKeyHandle, privKeyHandle);
}

CadErr CadmiumCrypto::dhDerive(uint32_t baseKeyHandle, const string& peerPublicKeyData,
        const Variant& derivedAlgObj, bool extractable, vector<KeyUsage> keyUsage,
        uint32_t& keyHandle)
{
    return impl_->dhDerive(baseKeyHandle, peerPublicKeyData, derivedAlgObj,
            extractable, keyUsage, keyHandle);
}

CadErr CadmiumCrypto::unwrapJwe(const string& jweData, uint32_t wrappingKeyHandle,
        const base::Variant& algVar, bool extractable, const vector<KeyUsage>& keyUsage,
        uint32_t& keyHandle)
{
    return impl_->unwrapJwe(jweData, wrappingKeyHandle, algVar, extractable,
            keyUsage, keyHandle);
}

CadErr CadmiumCrypto::wrapJwe(uint32_t toBeWrappedKeyHandle, uint32_t wrappingKeyHandle,
        const Variant& wrappingAlgoObj, JweEncMethod jweEncMethod, string& wrappedKeyJcs)
{
    return impl_->wrapJwe(toBeWrappedKeyHandle, wrappingKeyHandle, wrappingAlgoObj,
            jweEncMethod, wrappedKeyJcs);
}

CadErr CadmiumCrypto::pbkdf2Derive(const string& salt, uint32_t iterations,
        const base::Variant& prf, const string& password,
        const base::Variant& derivedAlgObj, bool extractable,
        const vector<KeyUsage> usage, uint32_t &keyHandle)
{
    return impl_->pbkdf2Derive(salt, iterations, prf, password, derivedAlgObj,
            extractable, usage, keyHandle);
}

CadErr CadmiumCrypto::getKeyByName(const string keyName, uint32_t &keyHandle, string& metadata)
{
    return impl_->getKeyByName(keyName, keyHandle, metadata);
}

CadErr CadmiumCrypto::getDeviceId(string& deviceId) const
{
    return impl_->getDeviceId(deviceId);
}

CadErr CadmiumCrypto::getSystemKeyHandle(uint32_t& systemKeyHandle) const
{
    return impl_->getSystemKeyHandle(systemKeyHandle);
}

string toString(CadmiumCrypto::Algorithm algorithm)
{
    switch (algorithm)
    {
        case CadmiumCrypto::HMAC:              return "HMAC";
        case CadmiumCrypto::AES_CBC:           return "AES-CBC";
        case CadmiumCrypto::AES_GCM:           return "AES-GCM";
        case CadmiumCrypto::AES_CTR:           return "AES-CTR";
        case CadmiumCrypto::RSAES_PKCS1_V1_5:  return "RSAES-PKCS1-v1_5";
        case CadmiumCrypto::RSASSA_PKCS1_V1_5: return "RSASSA-PKCS1-v1_5";
        case CadmiumCrypto::RSA_OAEP:          return "RSA-OAEP";
        case CadmiumCrypto::SHA1:              return "SHA-1";
        case CadmiumCrypto::SHA224:            return "SHA-224";
        case CadmiumCrypto::SHA256:            return "SHA-256";
        case CadmiumCrypto::SHA384:            return "SHA-384";
        case CadmiumCrypto::SHA512:            return "SHA-512";
        case CadmiumCrypto::AES_KW:            return "AES-KW";
        case CadmiumCrypto::DH:                return "DH";
        case CadmiumCrypto::PBKDF2:            return "PBKDF2";
        case CadmiumCrypto::SYSTEM:            return "SYSTEM";
        case CadmiumCrypto::INVALID_ALGORITHM:
        default:                               return "invalid";
    }
}

string toString(const vector<CadmiumCrypto::KeyUsage>& kusage)
{
    string output = "[ ";
    vector<CadmiumCrypto::KeyUsage>::const_iterator it;
    for (it = kusage.begin(); it != kusage.end(); ++it)
        output += toString(*it) + " ";
    output += "]";
    return output;
}

string toString(CadmiumCrypto::KeyType keyType)
{
    switch (keyType)
    {
        case CadmiumCrypto::SECRET:    return "secret";    break;
        case CadmiumCrypto::PUBLIC:    return "public";    break;
        case CadmiumCrypto::PRIVATE:   return "private";   break;
    }
    return "invalid";
}

string toString(CadmiumCrypto::KeyUsage keyUsage)
{
    switch (keyUsage)
    {
        case CadmiumCrypto::ENCRYPT:   return "encrypt";    break;
        case CadmiumCrypto::DECRYPT:   return "decrypt";    break;
        case CadmiumCrypto::SIGN:      return "sign";       break;
        case CadmiumCrypto::VERIFY:    return "verify";     break;
        case CadmiumCrypto::DERIVE:    return "derive";     break;
        case CadmiumCrypto::WRAP:      return "wrap";       break;
        case CadmiumCrypto::UNWRAP:    return "unwrap";     break;
    }
    return "invalid";
}

string toString(CadmiumCrypto::JweEncMethod jweEncMethod)
{
    switch (jweEncMethod)
    {
        case CadmiumCrypto::A128GCM: return "A128GCM"; break;
        case CadmiumCrypto::A256GCM: return "A256GCM"; break;
    }
    return "invalid";
}

bool isAlgorithmRsa(CadmiumCrypto::Algorithm algorithm)
{
    return ( algorithm == CadmiumCrypto::RSAES_PKCS1_V1_5  ||
             algorithm == CadmiumCrypto::RSASSA_PKCS1_V1_5 ||
             algorithm == CadmiumCrypto::RSA_OAEP             );
}
bool isAlgorithmAes(CadmiumCrypto::Algorithm algorithm)
{
    return ( algorithm == CadmiumCrypto::AES_CBC ||
             algorithm == CadmiumCrypto::AES_GCM ||
             algorithm == CadmiumCrypto::AES_CTR ||
             algorithm == CadmiumCrypto::AES_KW );
}

bool isAlgorithmHmac(CadmiumCrypto::Algorithm algorithm)
{
    return ( algorithm == CadmiumCrypto::HMAC );
}

bool isAlgorithmSha(CadmiumCrypto::Algorithm algorithm)
{
    return ( algorithm == CadmiumCrypto::SHA1   ||
             algorithm == CadmiumCrypto::SHA224 ||
             algorithm == CadmiumCrypto::SHA256 ||
             algorithm == CadmiumCrypto::SHA384 ||
             algorithm == CadmiumCrypto::SHA512    );
}

bool isAlgorithmDh(CadmiumCrypto::Algorithm algorithm)
{
    return ( algorithm == CadmiumCrypto::DH );
}

bool isAlgorithmPbkdf2(CadmiumCrypto::Algorithm algorithm)
{
    return ( algorithm == CadmiumCrypto::PBKDF2 );
}

CadmiumCrypto::Algorithm toAlgorithm(const string& algorithmStr)
{
    assert(gStr2AlgTab.size());
    if (!gStr2AlgTab.count(algorithmStr))
        return CadmiumCrypto::INVALID_ALGORITHM;
    return gStr2AlgTab[algorithmStr];
}

}} // namespace cadmium::crypto
