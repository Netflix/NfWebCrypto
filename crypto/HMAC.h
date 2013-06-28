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
#ifndef __HMAC_H__
#define __HMAC_H__

#include <memory>
#include <openssl/hmac.h>
#include <vector>
#include <base/Noncopyable.h>
#include <crypto/Digester.h>

namespace cadmium {
namespace crypto {

class DigestAlgo;

/**
 * Keyed Hash Message Authentication Code.
 * Keyed hash of data used for message authentication.
 */
class HMAC : private cadmium::base::Noncopyable {
public:
    /**
    * Constructor.
    * Constructs an HMAC object with the default hashing algorithm.
    * @param key the key used to compute an HMAC
    */
    HMAC(const std::vector<unsigned char> &key);

    /**
    * Constructor.
    * Constructs an HMAC object using the specified hashing algorithm.
    * @param key the key used to compute an HMAC
    */
    HMAC(const std::vector<unsigned char> &key,
         shared_ptr<const DigestAlgo> algo);

    /** Destructor. */
    ~HMAC();

    /**
    * Initialize this HMAC object for use.  Each HMAC object can be reused
    * after a call to final(), if init() is called for each session.
    */
    void init();

    /**
    * Add more data to the HMAC calculation.
    * @param data data to add to the calculation
    * @see final()
    */
    void update(const std::vector<unsigned char> &data);

    /**
    * Add more data to the HMAC calculation.
    * @param data data to add to the calculation
    * @len the length of the data
    */
    void update(const unsigned char *data, size_t len);

    /**
    * Complete the HMAC calculation.
    * @return the HMAC (not Base64 encoded).
    */
    std::vector<unsigned char> final();

    /**
    * Calculate HMAC of data & Base64 encode in a single call.
    * Internally this method calls:
    *   this->init();
    *   this->update(data);
    *   this->final();
    *   Base64::encode();
    * @param data data to HMAC.
    * @return Base64 encoded HMAC of data.
    */
    std::vector<unsigned char> hmac(const std::vector<unsigned char> &data);

    /**
    * Calculate HMAC of data & Base64 encode in a single call.
    * Internally this method calls:
    *   this->init();
    *   this->update(data);
    *   this->final();
    *   Base64::encode();
    * @param data data to HMAC.
    * @param len length of data.
    * @return Base64 encoded HMAC of data.
    */
    std::vector<unsigned char> hmac(const unsigned char *data, size_t len);

private:
    // object init method
    void initObj();
    const std::vector<unsigned char> key_;
    const shared_ptr<const DigestAlgo> algo_;
    HMAC_CTX ctx_;
};

}} // namespace cadmium::crypto

#endif // __HMAC_H__
