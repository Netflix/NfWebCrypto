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
#include "Pbkdf2.h"
#include <assert.h>
#include <openssl/evp.h>
#include "DigestAlgo.h"

using namespace std;
using namespace tr1;

namespace cadmium {
namespace crypto {

Pbkdf2::Pbkdf2(shared_ptr<const DigestAlgo> digestAlgo) : digestAlgo_(digestAlgo)
{
}

bool Pbkdf2::generate(const Vuc& salt, uint32_t iterations, const string& password,
        uint32_t keyLenBits, Vuc& out)
{
    assert(salt.size());
    assert(password.size());
    assert(iterations);
    assert(keyLenBits);

    // size the output
    const uint32_t keyLenBytes = keyLenBits / 8;
    out.resize(keyLenBytes);

    // do the operation
    const int ret = PKCS5_PBKDF2_HMAC(password.c_str(), password.size(),
        &salt[0], salt.size(), iterations, digestAlgo_->evp_md(), keyLenBytes,
        &out[0]);
    if (!ret)
        return false;

    // shrink to fit
    Vuc(out.begin(), out.end()).swap(out);

    return true;
}


}} // namespace cadmium:;crypto
