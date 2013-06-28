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
#include "OpenSSLException.h"
#include <stdlib.h>
#include <ostream>
#include <sstream>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <base/tr1.h>
#include <base/DebugUtil.h>

namespace {
/**
 * Returns the current OpenSSL error string.
 *
 * @return the OpenSSL error string or empty.
 */
std::string openssl_err()
{
    char *cstr = NULL;
    shared_ptr<BIO> err_bio(BIO_new(BIO_s_mem()), BIO_free);
    if (!err_bio.get())
    {
        DLOG() << "BIO_new(BIO_s_mem())\n";
        return "";
    }
    ERR_print_errors(err_bio.get());
    int len = BIO_get_mem_data(err_bio.get(), &cstr);
    if (len == 0 || cstr == NULL)
    {
        DLOG() << "BIO_get_mem_data(err_bio, &cstr)\n";
        return "";
    }
    std::string err(cstr);
    return err;
}
} // namespace anonymous

namespace cadmium {
namespace crypto {


OpenSSLException::OpenSSLException(const std::string& /*msg*/)
{}

OpenSSLException::OpenSSLException(const std::string& /*msg*/,
                                   const std::string& openssl_err)
    : openssl_err_(openssl_err)
{}

void OpenSSLException::throw_message(const char* msg, const char* file,
        int line, const char* function, bool doAbort)
{
    const std::string errstack = openssl_err();
    DLOG() << "OpenSSL Error: " << file << ":" << line
         << ":" << function << std::endl
         << "    '" << msg << "'" << std::endl
         << "    OpenSSL Error Stack:" << std::endl
         << "        " << errstack << std::endl;
    if (doAbort)
        ::abort();
}

}} // namespace cadmium::crypto
