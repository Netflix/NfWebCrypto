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

using namespace std;
using namespace tr1;

namespace cadmium {
namespace crypto {

Pbkdf2::Pbkdf2(shared_ptr<const DigestAlgo> digestAlgo) : digestAlgo_(digestAlgo)
{
}

Pbkdf2::~Pbkdf2()
{
}

bool Pbkdf2::generate(const Vuc& salt, uint32_t iterations, const string& password,
        uint32_t keyLen, Vuc& out)
{
    assert(salt.size());
    assert(password.size());
    assert(iterations);
    assert(keyLen);

    // size the output
    out.resize(keyLen >> 3);

//    int PKCS5_PBKDF2_HMAC(const char *pass, int passlen,
//                   const unsigned char *salt, int saltlen, int iter,
//                   const EVP_MD *digest,
//                  int keylen, unsigned char *out);

    return false;
}


}} // namespace cadmium:;crypto
