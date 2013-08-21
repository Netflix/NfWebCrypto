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

// NOTE: These are fake keys and ESN and will never work with Netflix
const string ESN      = "FAKE-MGK-0123456789";
const string kdeStr64 = "qNDCIUiIUjX1KzVFgzjObA==";
const string kdhStr64 = "wSROXN7yRYFzZO91rK7T4zeufNARl4jc3Lobeh58bYA=";
const string kdwStr64 = "svP4YtY3tVbqTScZdj0HXA==";

const string kdeName  = "Kde";
const string kdhName  = "Kdh";
const string kdwName  = "Kdw";

}   // anonymous namespace

SampleKeyProvision::SampleKeyProvision()
{
    const string esn64 = Base64::encode(ESN);
    const bool extractable = false;
    const CadmiumCrypto::KeyType type = CadmiumCrypto::SECRET;

    // provision the keys for all of the following origins
    vector<string> origins;
    origins.push_back("netflix.github.io");
    origins.push_back("localhost");

    Variant algVar;
    vector<CadmiumCrypto::KeyUsage> keyUsage;

    // ---- Kde
    // -- key data
    const CadmiumCrypto::Vuc kdeRaw(makeVuc(kdeStr64));
    assert(kdeRaw.size() == 128/8);
    // -- algorithm
    algVar = makeAlgVar(CadmiumCrypto::AES_CBC, kdeRaw.size() * 8);
    // -- keyUsage
    keyUsage.clear();
    keyUsage.push_back(CadmiumCrypto::ENCRYPT);
    keyUsage.push_back(CadmiumCrypto::DECRYPT);
    // -- provision this key
    addKey(kdeName, esn64, origins, kdeRaw, type, extractable, algVar, keyUsage);

    // ---- Kdh
    // -- key data
    const CadmiumCrypto::Vuc kdhRaw(makeVuc(kdhStr64));
    assert(kdhRaw.size() == 256/8);
    // -- algorithm
    algVar = makeAlgVar(CadmiumCrypto::HMAC, kdhRaw.size() * 8);
    // -- keyUsage
    keyUsage.clear();
    keyUsage.push_back(CadmiumCrypto::SIGN);
    keyUsage.push_back(CadmiumCrypto::VERIFY);
    // -- provision this key
    addKey(kdhName, esn64, origins, kdhRaw, type, extractable, algVar, keyUsage);

    // ---- Kdw
    // -- key data
    const CadmiumCrypto::Vuc kdwRaw(makeVuc(kdwStr64));
    assert(kdwRaw.size() == 128/8);
    // -- algorithm
    algVar = makeAlgVar(CadmiumCrypto::AES_KW, kdwRaw.size() * 8);
    // -- keyUsage
    keyUsage.clear();
    keyUsage.push_back(CadmiumCrypto::WRAP);
    keyUsage.push_back(CadmiumCrypto::UNWRAP);
    // -- provision this key
    addKey(kdwName, esn64, origins, kdwRaw, type, extractable, algVar, keyUsage);
}

}} // namespace cadmium::crypto
