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
#include "SampleKeyProvision.h"
#include <assert.h>
#include <vector>
#include <base/Base64.h>
#include <base/Variant.h>
#include <base/DebugUtil.h>

using namespace std;
using namespace cadmium::base;

namespace cadmium {
namespace crypto {

namespace
{

typedef vector<unsigned char> Vuc;

template<typename T, size_t N> T* begin(T (&arr)[N]) { return &arr[0];     }
template<typename T, size_t N> T* end(T (&arr)[N])   { return &arr[0] + N; }

VariantMap makeAlgVar(CadmiumCrypto::Algorithm algoType, int keyLength)
{
    assert(algoType == CadmiumCrypto::AES_CBC ||
           algoType == CadmiumCrypto::HMAC    ||
           algoType == CadmiumCrypto::AES_KW);
    VariantMap algVar;
    algVar["name"] = toString(algoType);
    if (algoType == CadmiumCrypto::HMAC)
    {
        string hashName;
        switch (keyLength)
        {
            case 160: hashName = toString(CadmiumCrypto::SHA1);   break;
            case 224: hashName = toString(CadmiumCrypto::SHA224); break;
            case 256: hashName = toString(CadmiumCrypto::SHA256); break;
            case 384: hashName = toString(CadmiumCrypto::SHA384); break;
            case 512: hashName = toString(CadmiumCrypto::SHA512); break;
            default:  assert(false);                              break;
        }
        algVar["params"]["hash"]["name"] = hashName;
    }
    return algVar;
}

}   // anonymous namespace

SampleKeyProvision::SampleKeyProvision()
{
    const string esn64 = Base64::encode("FAKE_ESN-0123-4567");
    const string originGithub("netflix.github.io");
    const string originLocalhost("localhost");
    const bool extractable = false;
    const CadmiumCrypto::KeyType type = CadmiumCrypto::SECRET;
    string name;
    Variant algVar;
    vector<CadmiumCrypto::KeyUsage> keyUsage;
    Vuc key;

    // -- sample Kpe
    name = "Kpe";
    // key data
    const size_t kpeLenBytes = 16;
    const unsigned char rawKpeAry[kpeLenBytes] =
    {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
    Vuc(begin(rawKpeAry), end(rawKpeAry)).swap(key);
    assert(key.size() == kpeLenBytes);
    // algorithm
    algVar = makeAlgVar(CadmiumCrypto::AES_CBC, key.size() * 8);
    // keyUsage
    keyUsage.clear();
    keyUsage.push_back(CadmiumCrypto::ENCRYPT);
    keyUsage.push_back(CadmiumCrypto::DECRYPT);
    // provision this key for both the GitHub and localhost origins
    NamedKey kpe(name, esn64, originGithub, key, type, extractable, algVar, keyUsage);
    namedKeyVec_.push_back(kpe);
    kpe.origin = originLocalhost;
    namedKeyVec_.push_back(kpe);

    // -- sample Kph
    name = "Kph";
    // key data
    const size_t kphLenBytes = 32;
    const unsigned char rawKphAry[kphLenBytes] =
    {0x0f,0x0e,0x0d,0x0c,0x0b,0x0a,0x09,0x08,0x07,0x06,0x05,0x04,0x03,0x02,0x01,0x01,
     0x0f,0x0e,0x0d,0x0c,0x0b,0x0a,0x09,0x08,0x07,0x06,0x05,0x04,0x03,0x02,0x01,0x01};
    Vuc(begin(rawKphAry), end(rawKphAry)).swap(key);
    assert(key.size() == kphLenBytes);
    // algorithm
    algVar = makeAlgVar(CadmiumCrypto::HMAC, key.size() * 8);
    // keyUsage
    keyUsage.clear();
    keyUsage.push_back(CadmiumCrypto::SIGN);
    keyUsage.push_back(CadmiumCrypto::VERIFY);
    // provision this key for both the GitHub and localhost origins
    NamedKey kph(name, esn64, originGithub, key, type, extractable, algVar, keyUsage);
    namedKeyVec_.push_back(kph);
    kph.origin = originLocalhost;
    namedKeyVec_.push_back(kph);

    // -- sample Kpw
    name = "Kpw";
    // key data
    const size_t kpwLenBytes = 16;
    const unsigned char rawKpwAry[kpwLenBytes] =
    {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
    Vuc(begin(rawKpwAry), end(rawKpwAry)).swap(key);
    assert(key.size() == kpwLenBytes);
    // algorithm
    algVar = makeAlgVar(CadmiumCrypto::AES_KW, key.size() * 8);
    // keyUsage
    keyUsage.clear();
    keyUsage.push_back(CadmiumCrypto::WRAP);
    keyUsage.push_back(CadmiumCrypto::UNWRAP);
    // provision this key for both the GitHub and localhost origins
    NamedKey kpw(name, esn64, originGithub, key, type, extractable, algVar, keyUsage);
    namedKeyVec_.push_back(kpw);
    kpw.origin = originLocalhost;
    namedKeyVec_.push_back(kpw);
}

}} // namespace cadmium::crypto
