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
#ifndef KEY_H_
#define KEY_H_
#include <tr1/memory>
#include <vector>
#include <base/Variant.h>
#include "CadmiumCrypto.h"
#include "RsaContext.h"
#include "DiffieHellmanContext.h"

namespace cadmium {
namespace crypto {

struct Key
{
    typedef std::vector<unsigned char> Vuc;
    // raw keying material for a symmetric key
    Vuc key;
    // RSA context for an RSA key
    std::tr1::shared_ptr<RsaContext> pRsaContext;
    // Diffie-Hellman context for a DH key
    std::tr1::shared_ptr<DiffieHellmanContext> pDhContext;
    // the type of the key: secret (symmetric), public, or private
    CadmiumCrypto::KeyType type;
    // able use exportKey() or not on this key
    bool extractable;
    // the algorithm this key is used for
    base::Variant algVar;
    // the allowed usages of this key, empty for all use
    std::vector<CadmiumCrypto::KeyUsage> keyUsage;
    virtual ~Key() {}
    Key();
    Key(const Vuc& key, CadmiumCrypto::KeyType kt, bool extractable,
            const base::Variant& algVar,
            const std::vector<CadmiumCrypto::KeyUsage>& usg);
    Key(const Vuc& key, std::tr1::shared_ptr<RsaContext> pRsaContext,
        CadmiumCrypto::KeyType kt, bool extractable, const base::Variant& algVar,
        const std::vector<CadmiumCrypto::KeyUsage>& usg);
    Key(const Vuc& key, std::tr1::shared_ptr<DiffieHellmanContext> pDhContext,
        CadmiumCrypto::KeyType kt, bool extractable, const base::Variant& algVar,
        const std::vector<CadmiumCrypto::KeyUsage>& usg);
    // default copy ctor and assignment operator OK, let the compiler define
};

struct NamedKey : public Key
{
    std::string name;   // the pre-provisioned name of this key
    std::string id;     // the pre-provisioned meta data; often the device ESN
    std::vector<std::string> origins; // the pre-provisioned origins where this key is valid
    virtual ~NamedKey() {}
    NamedKey(const std::string& name, const std::string& id,
            const std::vector<std::string>& origin, const Vuc& key,
            CadmiumCrypto::KeyType type, bool extractable,
            const base::Variant& algVar,
            const std::vector<CadmiumCrypto::KeyUsage>& usg);
};

}} // namespace cadmium::crypto
#endif // KEY_H_
