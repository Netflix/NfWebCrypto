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
#ifndef AESGCMCIPHER_H_
#define AESGCMCIPHER_H_
#include <vector>
#include <openssl/bn.h>

namespace cadmium {
namespace crypto {

class AesGcmCipher
{
public:
    typedef std::vector<unsigned char> Vuc;
    AesGcmCipher(const Vuc& key, const Vuc& iv);
    ~AesGcmCipher();
    bool encrypt(const Vuc& clearText, const Vuc& aad, Vuc& cipherText, Vuc& mac);
    bool decrypt(const Vuc& cipherText, const Vuc& aad, const Vuc& mac, Vuc& clearText);
    enum KeyLength { KL128=16, KL192=24, KL256=32 };
private:
    const EVP_CIPHER* getCipher() const;
private:
    const Vuc key_;
    const Vuc iv_;
    const KeyLength keyLength_;
};

}} // namespace cadmium::crypto

#endif /* AESGCMCIPHER_H_ */
