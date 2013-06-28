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
#include <crypto/Digester.h>
#include <crypto/OpenSSLException.h>

namespace cadmium {
namespace crypto {

Digester::Digester(shared_ptr<const DigestAlgo> algo)
    : algo_(algo)
{
    pctx_ = EVP_MD_CTX_create();
}

Digester::~Digester()
{
    EVP_MD_CTX_cleanup(pctx_);
    EVP_MD_CTX_destroy(pctx_);
}

void Digester::init()
{
    if(!(EVP_DigestInit_ex(pctx_, algo_->evp_md(), NULL))) {
        OPENSSLEXCEPTION_MSG("EVP_DigestInit_ex()");
    }
}

void Digester::update(const std::vector<unsigned char> &data)
{
    update(&data[0], data.size());
}

void Digester::update(const unsigned char *data, size_t sz)
{
    if(!(EVP_DigestUpdate(pctx_, data, sz))) {
        OPENSSLEXCEPTION_MSG("EVP_DigestUpdate()");
    }
}

void Digester::update(const std::string &data)
{
    update((const unsigned char *)data.data(), data.size());
}

std::vector<unsigned char> Digester::final()
{
    std::vector<unsigned char> buf(EVP_MAX_MD_SIZE);
    unsigned int buf_len = 0;
    if(!(EVP_DigestFinal_ex(pctx_, &buf[0], &buf_len))) {
        OPENSSLEXCEPTION_MSG("EVP_DigestFinal_ex()");
    }
    buf.resize(buf_len);
    return buf;
}

}} // namespace cadmium::crypto
