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
#include "Base64.h"
#include <iterator>
#include <algorithm>

namespace cadmium {
namespace base {
namespace Base64 {

std::string encode(std::string const& s) {
  std::string value;
  encode(s.begin(), s.end(), std::back_inserter(value));
  return value;
}

std::string decode(std::string const& s) {
  std::string value;
  decode(s.begin(), s.end(), std::back_inserter(value));
  return value;
}

std::vector<unsigned char> encode(std::vector<unsigned char> const& v) {
  std::vector<unsigned char> value;
  encode(v.begin(), v.end(), std::back_inserter(value));
  return value;
}

std::vector<unsigned char> decode(std::vector<unsigned char> const& v) {
  std::vector<unsigned char> value;
  decode(v.begin(), v.end(), std::back_inserter(value));
  return value;
}

// URL-safe variants, from
// http://tools.ietf.org/html/draft-ietf-jose-json-web-signature-08#appendix-C

std::string encodeUrlSafe(std::string const& s)
{
    std::vector<unsigned char> v(s.begin(), s.end());
    std::vector<unsigned char> ve = encodeUrlSafe(v);
    return std::string(ve.begin(), ve.end());
}

std::string decodeUrlSafe(std::string const& s)
{
    std::vector<unsigned char> v(s.begin(), s.end());
    std::vector<unsigned char> vd = decodeUrlSafe(v);
    return std::string(vd.begin(), vd.end());
}

std::vector<unsigned char> encodeUrlSafe(std::vector<unsigned char> const& v)
{
    // Regular base64 encoder
    std::vector<unsigned char> vv = encode(v);
    // Remove any trailing "="s
    vv.erase(remove(vv.begin(), vv.end(), '='), vv.end());
    // 62nd char of encoding
    std::replace(vv.begin(), vv.end(), '+', '-');
    // 63rd char of encoding
    std::replace(vv.begin(), vv.end(), '/', '_');
    return vv;
}

std::vector<unsigned char> decodeUrlSafe(std::vector<unsigned char> const& v)
{
    std::vector<unsigned char> vv(v);
    // 62nd char of encoding
    std::replace(vv.begin(), vv.end(), '-', '+');
    // 63rd char of encoding
    std::replace(vv.begin(), vv.end(), '_', '/');
    switch (vv.size() % 4)
    {
        case 0:
            break;  // No pad chars in this case
        case 2:
            vv.push_back('=');  // Two pad chars
            vv.push_back('=');
            break;
        case 3:
            vv.push_back('=');  // One pad char
            break;
        default:
            vv.clear();     // encoding error!
            break;
    }
    // Standard base64 decoder
    return decode(vv);
}

} // namespace Base64
} // namespace base
} // namespace cadmium
