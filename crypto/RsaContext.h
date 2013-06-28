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
#ifndef RSACONTEXT_H_
#define RSACONTEXT_H_
#include <stdint.h>
#include <vector>
#include <openssl/evp.h>

namespace cadmium {
namespace crypto {

class RsaContext
{
public:
    typedef std::vector<unsigned char> Vuc;
    enum ShaAlgo {SHA1, SHA224, SHA256, SHA384, SHA512};
    enum Padding {NONE, PKCS1, PKCS1_OAEP};
public:
    RsaContext();
    ~RsaContext();
    bool generate(uint32_t nBits, uint64_t publicExponent);
    bool setRaw(const Vuc & pubMod, const Vuc & pubExp, const Vuc & privMod);
    bool setPrivatePkcs8(const Vuc & pkcs8);
    bool getPrivatePkcs8(Vuc & pkcs8) const;
    bool getPublicRaw(Vuc & pubMod, Vuc & pubExp);
    bool setPublicPkcs1(const Vuc & pubKeyPkcs1Der);
    bool getPublicPkcs1(Vuc & pubKeyPkcs1Der) const;
    bool setPublicSpki(const Vuc & pubKeySpkiDer);
    bool getPublicSpki(Vuc & pubKeySpkiDer) const;
    bool setPrivatePkcs1(const Vuc & privKeyPkcs1Der);
    bool getPrivatePkcs1(Vuc & privKeyPkcs1Der) const;
    bool publicEncrypt(const Vuc & in, Vuc & out, Padding padding = PKCS1);
    bool privateDecrypt(const Vuc & in, Vuc & out, Padding padding = PKCS1);
    bool privateSign(const Vuc & data, ShaAlgo shaAlgo, Vuc & sig);
    bool publicVerify(const Vuc & data, ShaAlgo shaAlgo, const Vuc & sig);
    bool hasPublicKey() const {return hasPublicKey_;}
private:
    Vuc computeDigest(const Vuc & data, ShaAlgo shaAlgo);
private:
    RSA * pOsslRsa_;
    bool hasPrivateKey_;
    bool hasPublicKey_;
};

}} // namespace cadmium::crypto

#endif // RSACONTEXT_H_
