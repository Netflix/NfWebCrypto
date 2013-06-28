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
#ifndef __BIGNUM_H__
#define __BIGNUM_H__

#include <string>
#include <vector>
#include <openssl/bn.h>
#include <base/tr1.h>
#include "ScopedOpenSSL.h"

namespace cadmium {
namespace crypto {

/**
 * C++ wrapper of OpenSSL BIGNUM values.
 * @author mzollinger.
 */
class BigNum {
public:
    explicit BigNum(const std::vector<unsigned char> &data);
    explicit BigNum(const BIGNUM *val = 0);
    static BigNum fromBase64(const std::vector<unsigned char> &b64);
    BigNum(const unsigned char *buf, size_t sz);
    BigNum(const BigNum &rhs);
    bool operator==(const BigNum &rhs) const;
    bool operator!=(const BigNum &rhs) const;
    std::vector<unsigned char> toBase64() const;
    std::vector<unsigned char> encode() const;
    size_t size() const;
    BIGNUM * const getBIGNUM() const;
    std::string toString() const;
    std::string toFormatString(const std::string &name, size_t width, size_t indent_level,
                            const std::string &delim, size_t indent_len) const;
    std::string toFormatString(const std::string &name, size_t width,
                            size_t indent_level) const;
    std::string toFormatString(const std::string &name) const;
private:
    BigNum & operator=(const BigNum &rhs);  // not implemented
    typedef ScopedOpenSSL<BIGNUM, BN_free> SafeBignum;
    SafeBignum val_;
};

}} // namespace cadmium::crypto

#endif // __BIGNUM_H__
