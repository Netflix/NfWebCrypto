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
#include "Random.h"
#include <openssl/rand.h>
#include "NtbaLog.h"

using namespace std;

namespace cadmium {
namespace crypto {
namespace random {

vector<unsigned char> next(size_t num_bytes)
{
    vector<unsigned char> val(num_bytes, 0);
    if(!(RAND_bytes(&val[0], num_bytes)))
    {
        log_err("RAND_bytes error!")
        ::abort();
    }
    return val;
}

}}} // namespace cadmium::crypto::random
