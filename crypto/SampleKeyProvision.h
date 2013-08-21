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
#ifndef SAMPLEKEYPROVISION_H_
#define SAMPLEKEYPROVISION_H_

#include "IKeyProvision.h"
#include <vector>
#include <string>
#include <base/Base64.h>

namespace cadmium {
namespace crypto {

/**
 * Sample key pre-provision implementation
 * NOTE: This is for sample purposes only! In a real implementation pre-
 * provisioned keys will come somehow from a secure place.
 */
class SampleKeyProvision: public IKeyProvision
{
public:
	SampleKeyProvision();
	virtual ~SampleKeyProvision() {}
private:
	void addKey(const std::string& name, const std::string& esn64,
	        const std::vector<std::string>& origins, const CadmiumCrypto::Vuc& key,
	        CadmiumCrypto::KeyType type, bool extractable, const base::Variant& algVar,
	        const std::vector<CadmiumCrypto::KeyUsage>& keyUsage)
	{
	    NamedKey nk(name, esn64, origins, key, type, extractable, algVar, keyUsage);
	    namedKeyVec_.push_back(nk);
	}
	base::VariantMap makeAlgVar(CadmiumCrypto::Algorithm algoType, int keyLength)
	{
	    assert(algoType == CadmiumCrypto::AES_CBC ||
	           algoType == CadmiumCrypto::HMAC    ||
	           algoType == CadmiumCrypto::AES_KW);
	    base::VariantMap algVar;
	    algVar["name"] = toString(algoType);
	    if (algoType == CadmiumCrypto::HMAC)
	    {
	        std::string hashName;
	        switch (keyLength)
	        {
	            case 160: hashName = toString(CadmiumCrypto::SHA1);   break;
	            case 224: hashName = toString(CadmiumCrypto::SHA224); break;
	            case 256: hashName = toString(CadmiumCrypto::SHA256); break;
	            case 384: hashName = toString(CadmiumCrypto::SHA384); break;
	            case 512: hashName = toString(CadmiumCrypto::SHA512); break;
	            default:  assert(false);                              break;
	        }
	        algVar["params"]["hash"]["name"] = hashName;
	    }
	    return algVar;
	}
	CadmiumCrypto::Vuc makeVuc(const std::string& dataStr64)
	{
	    const CadmiumCrypto::Vuc dataVec64(dataStr64.begin(), dataStr64.end());
	    return CadmiumCrypto::Vuc(base::Base64::decode(dataVec64));
	}
};

}} // namespace cadmium::crypto

#endif // SAMPLEKEYPROVISION_H_
