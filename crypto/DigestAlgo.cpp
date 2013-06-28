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
#include "DigestAlgo.h"
#include <openssl/evp.h>
#include <openssl/obj_mac.h>

namespace cadmium {
namespace crypto {

shared_ptr<const DigestAlgo> DigestAlgo::SHA1()
{
    shared_ptr<const DigestAlgo> da(new DigestAlgo("SHA1", NID_sha1, EVP_sha1()));
    return da;
}

shared_ptr<const DigestAlgo> DigestAlgo::SHA224()
{
    shared_ptr<const DigestAlgo> da(new DigestAlgo("SHA224", NID_sha224, EVP_sha224()));
    return da;
}

shared_ptr<const DigestAlgo> DigestAlgo::SHA256()
{
    shared_ptr<const DigestAlgo> da(new DigestAlgo("SHA256", NID_sha256, EVP_sha256()));
    return da;
}

shared_ptr<const DigestAlgo> DigestAlgo::SHA384()
{
    shared_ptr<const DigestAlgo> da(new DigestAlgo("SHA384", NID_sha384, EVP_sha384()));
    return da;
}

shared_ptr<const DigestAlgo> DigestAlgo::SHA512()
{
    shared_ptr<const DigestAlgo> da(new DigestAlgo("SHA512", NID_sha512, EVP_sha512()));
    return da;
}

DigestAlgo::DigestAlgo(const std::string name, int nid, const EVP_MD *evp_md)
    : name_(name), nid_(nid), evp_md_(evp_md)
{}

}}  // namespace cadmium::crypto
