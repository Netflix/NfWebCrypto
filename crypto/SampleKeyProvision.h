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
    virtual NamedKeyVec& getNamedKeyVec() {return namedKeyVec_;}
private:
    NamedKeyVec namedKeyVec_;
};

}} // namespace cadmium::crypto

#endif // SAMPLEKEYPROVISION_H_
