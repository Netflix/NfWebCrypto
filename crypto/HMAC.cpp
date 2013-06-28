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
#include "HMAC.h"
#include <openssl/hmac.h>
#include <base/Base64.h>
#include "NtbaLog.h"

namespace cadmium {
namespace crypto {

HMAC::HMAC(const std::vector<unsigned char> &key)
    : key_(key), algo_(DigestAlgo::SHA256())
{
    initObj();
}

HMAC::HMAC(const std::vector<unsigned char> &key,
                          shared_ptr<const DigestAlgo> algo)
    : key_(key), algo_(algo)
{
    initObj();
}

void HMAC::initObj()
{
    // TODO: put a size requirement on the key
    //md_ = Digester::typeToEVP(type_);
    HMAC_CTX_init(&ctx_);
    HMAC_Init(&ctx_, (const void *)&key_[0], key_.size(), algo_->evp_md());
}

HMAC::~HMAC()
{
    HMAC_cleanup(&ctx_);
}

void HMAC::init()
{
    // use of HMAC_Init_ex with key == NULL reuses previous key
    // use of HMAC_Init_ex with EVP_MD == NULL reuses previous EVP_MD
    HMAC_Init_ex(&ctx_, /*key*/NULL, /*key_len*/0, /*EVP_MD*/NULL, /*ENGINE*/NULL);
}

void HMAC::update(const std::vector<unsigned char> &data)
{
    update(&data[0], data.size());
}

void HMAC::update(const unsigned char *data, size_t len)
{
    HMAC_Update(&ctx_, data, len);
}

std::vector<unsigned char> HMAC::final()
{
    std::vector<unsigned char> md(EVP_MAX_MD_SIZE);
    unsigned int sz = 0;

    HMAC_Final(&ctx_, &md[0], &sz);
    log_dbg("HMAC_Final returned md of size: %d", sz);
    md.resize(sz);
    return md;
}

std::vector<unsigned char> HMAC::hmac(const std::vector<unsigned char> &data)
{
    return hmac(&data[0], data.size());
}

std::vector<unsigned char> HMAC::hmac(const unsigned char *data, size_t len)
{
    init();
    update(data, len);
    std::vector<unsigned char> hmac = final();
    std::vector<unsigned char> b64hmac = cadmium::base::Base64::encode(hmac);
    return b64hmac;
}

}} // namespace cadmium::crypto
