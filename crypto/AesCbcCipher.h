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
#ifndef AESCBCCIPHER_H_
#define AESCBCCIPHER_H_
#include <stdint.h>
#include <vector>
#include <openssl/aes.h>
#include <openssl/bn.h>

namespace cadmium {
namespace crypto {

class AesCbcCipher
{
public:
    typedef std::vector<unsigned char> Vuc;
    AesCbcCipher(const Vuc& key, const Vuc& iv);
    ~AesCbcCipher();
    bool encrypt(const Vuc& clear, Vuc& encrypted);
    bool decrypt(const Vuc& encrypted, Vuc& clear);
    static const uint32_t BLOCKSIZE = AES_BLOCK_SIZE;
    enum KeyLength { KL128=16, KL192=24, KL256=32 };
private:
    const EVP_CIPHER* getCipher() const;
private:
    const Vuc key_;
    const Vuc iv_;
    const KeyLength keyLength_;
};

}} // namespace cadmium::rypto

#endif /* AESCBCCIPHER_H_ */
