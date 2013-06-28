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
#include "BigNum.h"
#include <string>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <base/tr1.h>
#include <base/Base64.h>
#include "NtbaLog.h"
#include "NtbaUtil.h"
#include "OpenSSLException.h"
#include "ScopedOpenSSL.h"

using namespace cadmium::base;

namespace cadmium {
namespace crypto {

BigNum::BigNum(const BIGNUM *val)
    : val_(val ? BN_dup(val) : BN_new())
{
    if (!val_.get()) OPENSSLEXCEPTION_MSG("BN_dup/BN_new");
}

BigNum::BigNum(const std::vector<unsigned char> &data)
    : val_(BN_bin2bn(&data[0], data.size(), NULL))
{
    if (!val_.get()) OPENSSLEXCEPTION_MSG("BN_bin2bn");
}

BigNum::BigNum(const unsigned char *buf, size_t sz)
    : val_(BN_bin2bn(buf, sz, NULL))
{
    if (!val_.get()) OPENSSLEXCEPTION_MSG("BN_bin2bn()");
}

BigNum BigNum::fromBase64(const std::vector<unsigned char> &b64)
{
    return BigNum(Base64::decode(b64));
}

BigNum::BigNum(const BigNum &rhs)
    : val_(BN_dup(rhs.val_.get()))
{
    if (!val_.get()) OPENSSLEXCEPTION_MSG("BN_dup()");
}

bool BigNum::operator==(const BigNum &rhs) const
{
    return BN_cmp(val_.get(), rhs.val_.get()) == 0;
}

bool BigNum::operator!=(const BigNum &rhs) const
{
    return !(operator==(rhs));
}

std::vector<unsigned char> BigNum::toBase64() const
{
    return Base64::encode(encode());
}

std::vector<unsigned char> BigNum::encode() const
{
    std::vector<unsigned char> buf(size());
    BN_bn2bin(val_.get(), &buf[0]);
    return buf;
}

size_t BigNum::size() const
{
    return BN_num_bytes(val_.get());
}

BIGNUM * const BigNum::getBIGNUM() const
{
    return val_.get();
}

std::string BigNum::toString() const
{
    ScopedOpenSSL<BIO, BIO_vfree> bio(BIO_new(BIO_s_mem()));
    if(! BN_print(bio.get(), val_.get())) {
        OPENSSLEXCEPTION_MSG("BN_print() in BigNum::toString()");
    }
    // get number of bytes in bio
    size_t len = BIO_ctrl_pending(bio.get());
    std::vector<unsigned char> out(len);
    if(! BIO_read(bio.get(), &out[0], len)) {
        OPENSSLEXCEPTION_MSG("BIO_read() in BigNum::toString()");
    }
    return std::string(reinterpret_cast<const char*>(&out[0]), out.size());
}

std::string BigNum::toFormatString
    (const std::string &name, size_t width, size_t indent_level,
     const std::string &delim, size_t indent_len) const
{
    std::vector<unsigned char> data = encode();
    return NtbaUtil::toFormatHexString
        (&data[0], data.size(), name, width, indent_level, delim, indent_len);
}

#if 0
std::string BigNum::toFormatString
    (const std::string &name, size_t width, size_t indent_level) const
{
    return toFormatString(name, width, indent_level, Env::get_hex_delim(),
                          Env::get_indent_spaces());
}

std::string BigNum::toFormatString(const std::string &name) const
{
    return toFormatString(name, Env::get_screen_width(), Env::get_indent_level());
}
#endif

}} // namespace cadmium::crypto
