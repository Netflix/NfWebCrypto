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
#include "Key.h"

using namespace std;
using namespace tr1;

namespace cadmium {

using namespace base;

namespace crypto {

Key::Key()
:   type(CadmiumCrypto::SECRET)
,   extractable(false)
{
}

Key::Key(const Vuc& key, CadmiumCrypto::KeyType type, bool extractable,
        const base::Variant& algVar, const vector<CadmiumCrypto::KeyUsage>& keyUsage)
:   key(key)
,   type(type)
,   extractable(extractable)
,   algVar(algVar)
,   keyUsage(keyUsage)
{
}


Key::Key(const Vuc& key, shared_ptr<RsaContext> pRsaContext,
        CadmiumCrypto::KeyType type, bool extractable, const Variant& algVar,
        const vector<CadmiumCrypto::KeyUsage>& keyUsage)
:   key(key)
,   pRsaContext(pRsaContext)
,   type(type)
,   extractable(extractable)
,   algVar(algVar)
,   keyUsage(keyUsage)
{
}

Key::Key(const Vuc& key, shared_ptr<DiffieHellmanContext> pDhContext,
        CadmiumCrypto::KeyType type, bool extractable, const Variant& algVar,
        const vector<CadmiumCrypto::KeyUsage>& keyUsage)
:   key(key)
,   pDhContext(pDhContext)
,   type(type)
,   extractable(extractable)
,   algVar(algVar)
,   keyUsage(keyUsage)
{
}

NamedKey::NamedKey(const string& name, const string& id,
        const vector<string>& origins, const Vuc& key, CadmiumCrypto::KeyType kt,
        bool extractable, const base::Variant& algVar,
        const vector<CadmiumCrypto::KeyUsage>& usg)
:   Key(key, kt, extractable, algVar, usg)
,   name(name)
,   id(id)
,   origins(origins)
{
}

}} // namespace cadmium::crypto
