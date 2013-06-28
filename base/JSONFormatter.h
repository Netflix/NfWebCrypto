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
#ifndef JSONFormatter_h
#define JSONFormatter_h
#include <string>
#include <stdint.h>

namespace cadmium {
namespace base {

class Variant;

class JSONFormatter
{
public:
    enum Flag {
        None = 0x0,
        NullVariantToEmptyString = 0x1,
        Pretty = 0x02
    };
    JSONFormatter(uint32_t flags = None);
    ~JSONFormatter() {}
    std::string format(const Variant &variant, int indent=0) const;
    const char *mimeType() const;
    uint32_t flags() const { return mFlags; }
private:
    static std::string formatIndent(int indent);
    const uint32_t mFlags;
};

}}  // namespace cadmium::base

#endif
