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
#ifndef __DIGESTALGO_H__
#define __DIGESTALGO_H__

#include <memory>
#include <string>
#include <openssl/evp.h>
#include <base/tr1.h>
#include <base/Noncopyable.h>

namespace cadmium {
namespace crypto {

/**
 * Digest Algorithm.
 */
class DigestAlgo : private cadmium::base::Noncopyable {
public:
    static shared_ptr<const DigestAlgo> SHA1();
    static shared_ptr<const DigestAlgo> SHA224();
    static shared_ptr<const DigestAlgo> SHA256();
    static shared_ptr<const DigestAlgo> SHA384();
    static shared_ptr<const DigestAlgo> SHA512();

    int nid() const { return nid_; }
    const EVP_MD * evp_md() const { return evp_md_; }
    std::string toString() const { return name_; }

private:
    DigestAlgo(const std::string name, int nid, const EVP_MD *evp_md);
    const std::string name_;
    const int nid_;
    const EVP_MD *evp_md_;
};

}} // namespace cadmium::crypto

#endif // __DIGESTALGO_H__
