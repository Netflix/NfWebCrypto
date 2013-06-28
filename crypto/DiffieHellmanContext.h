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
#ifndef DIFFIEHELLMANSESSION_H_
#define DIFFIEHELLMANSESSION_H_
#include <vector>
#include <tr1/memory>
#include <openssl/bn.h>

namespace cadmium {
namespace crypto {

class DiffieHellmanContext
{
public:
    typedef std::vector<unsigned char> Vuc;
    DiffieHellmanContext();
    ~DiffieHellmanContext();
    bool init(const Vuc& p, const Vuc& g);
    Vuc getPubKey() const;
    Vuc getPrivKey() const;
    bool computeSharedSecret(const Vuc& peerPubKey);
    Vuc getSharedSecret() const;
private:
    std::tr1::shared_ptr<DH> dh_;
    Vuc sharedSecret_;
};

}} // namespace cadmium::crypto

#endif // DIFFIEHELLMANSESSION_H_
