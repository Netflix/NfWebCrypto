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

SampleKeyProvision::SampleKeyProvision()
{
    const string esn64 = Base64::encode("FAKE_ESN-0123-4567");
    const bool extractable = false;
    const CadmiumCrypto::KeyType type = CadmiumCrypto::SECRET;

    // provision the keys for all of the following origins
    vector<string> origins;
    origins.push_back("netflix.github.io");
    origins.push_back("localhost");

    string name;
    CadmiumCrypto::Vuc key;
    Variant algVar;
    vector<CadmiumCrypto::KeyUsage> keyUsage;

    // -- sample Kpe
    name = "Kpe";
    // key data
    const size_t kpeLenBytes = 16;
    const unsigned char rawKpeAry[kpeLenBytes] =
    {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
    CadmiumCrypto::Vuc(begin(rawKpeAry), end(rawKpeAry)).swap(key);
    assert(key.size() == kpeLenBytes);
    // algorithm
    algVar = makeAlgVar(CadmiumCrypto::AES_CBC, key.size() * 8);
    // keyUsage
    keyUsage.clear();
    keyUsage.push_back(CadmiumCrypto::ENCRYPT);
    keyUsage.push_back(CadmiumCrypto::DECRYPT);
    // provision this key
    addKey(name, esn64, origins, key, type, extractable, algVar, keyUsage);

    // -- sample Kph
    name = "Kph";
    // key data
    const size_t kphLenBytes = 32;
    const unsigned char rawKphAry[kphLenBytes] =
    {0x0f,0x0e,0x0d,0x0c,0x0b,0x0a,0x09,0x08,0x07,0x06,0x05,0x04,0x03,0x02,0x01,0x01,
     0x0f,0x0e,0x0d,0x0c,0x0b,0x0a,0x09,0x08,0x07,0x06,0x05,0x04,0x03,0x02,0x01,0x01};
    CadmiumCrypto::Vuc(begin(rawKphAry), end(rawKphAry)).swap(key);
    assert(key.size() == kphLenBytes);
    // algorithm
    algVar = makeAlgVar(CadmiumCrypto::HMAC, key.size() * 8);
    // keyUsage
    keyUsage.clear();
    keyUsage.push_back(CadmiumCrypto::SIGN);
    keyUsage.push_back(CadmiumCrypto::VERIFY);
    // provision this key
    addKey(name, esn64, origins, key, type, extractable, algVar, keyUsage);

    // -- sample Kpw
    name = "Kpw";
    // key data
    const size_t kpwLenBytes = 16;
    const unsigned char rawKpwAry[kpwLenBytes] =
    {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
    CadmiumCrypto::Vuc(begin(rawKpwAry), end(rawKpwAry)).swap(key);
    assert(key.size() == kpwLenBytes);
    // algorithm
    algVar = makeAlgVar(CadmiumCrypto::AES_KW, key.size() * 8);
    // keyUsage
    keyUsage.clear();
    keyUsage.push_back(CadmiumCrypto::WRAP);
    keyUsage.push_back(CadmiumCrypto::UNWRAP);
    // provision this key
    addKey(name, esn64, origins,key, type, extractable, algVar, keyUsage);
}

}} // namespace cadmium::crypto
