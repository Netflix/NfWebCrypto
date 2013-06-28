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
#ifndef __DIGESTER_H__
#define __DIGESTER_H__

#include <memory>
#include <vector>
#include <openssl/evp.h>
#include <base/tr1.h>
#include <crypto/DigestAlgo.h>

namespace cadmium {
namespace crypto {

/**
 * @class Digester Digester.h
 * @brief Digester for hashing data using SHA1, etc.
 */
class Digester
{
public:
    /**
     * Create a digester using a hashing algorithm
     *
     * @param[in] algo The hash algorithm to use
     */
    Digester(shared_ptr<const DigestAlgo> algo);
    ~Digester();

    /**
     * Initialize the digester
     */
    void init();

    /**
     * Update the accumulated hash with the new data
     *
     * @param[in] data new data to add to hash
     * @param[in] sz size of new data
     */
    void update(const std::vector<unsigned char> &data);
    void update(const unsigned char *data, size_t sz);
    void update(const std::string &data);

    /**
     * Get the final hash of the data
     *
     * @return the hash of the accumulated data
     */
    std::vector<unsigned char> final();

    /**
     * Gets the hashing algortihm
     *
     * @return the digester's hashing algorithm
     */
    shared_ptr<const DigestAlgo> algo() const { return algo_; }

private:
    const shared_ptr<const DigestAlgo> algo_;
    EVP_MD_CTX * pctx_;
};

}} // namespace cadmium::crypto

#endif // __DIGESTER_H__
