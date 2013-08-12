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
#ifndef PBKDF2_H_
#define PBKDF2_H_
#include <stdint.h>
#include <vector>
#include <string>
#include <tr1/memory>
#include "DigestAlgo.h"

namespace cadmium {
namespace crypto {

class Pbkdf2
{
public:
    Pbkdf2(std::tr1::shared_ptr<const DigestAlgo> algo);
    ~Pbkdf2() {}
    typedef std::vector<unsigned char> Vuc;
    bool generate(const Vuc& salt, uint32_t iterations, const std::string& password,
            uint32_t keyLen, Vuc& out);
private:
    const shared_ptr<const DigestAlgo> digestAlgo_;
};

}} // namespace cadmium::crypto

#endif // PBKDF2_H_
