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
#ifndef IKEYPROVISION_H_
#define IKEYPROVISION_H_
#include <vector>
#include "Key.h"

namespace cadmium {
namespace crypto {

/** Interface for the class holding pre-provisioned symmetric keys.
 * The implementation of this class will depend on the device.
 */
class IKeyProvision
{
public:
	typedef std::vector<NamedKey> NamedKeyVec;
	NamedKeyVec& getNamedKeyVec() {return namedKeyVec_;}
protected:
	virtual ~IKeyProvision() {}
    NamedKeyVec namedKeyVec_;

};

}} // namespace cadmium::crypto

#endif // IKEYPROVISION_H_
