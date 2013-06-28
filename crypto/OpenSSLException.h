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
#ifndef __OPENSSLEXCEPTION_H__
#define __OPENSSLEXCEPTION_H__

#include <string>

#define OPENSSLEXCEPTION_MSG(msg) \
    cadmium::crypto::OpenSSLException::throw_message(msg, __FILE__, __LINE__, __FUNCTION__)

#define OPENSSLERROR_MSG(msg) \
    cadmium::crypto::OpenSSLException::throw_message(msg, __FILE__, __LINE__, __FUNCTION__, false)

#define OPENSSLEXCEPTION OPENSSLEXCEPTION_MSG("General OpenSSL Error")

namespace cadmium {
namespace crypto {

/**
 * @class OpenSSLException OpenSSLException.hpp
 * @brief Exception thrown when an OpenSSL library error occurs.
 */
class OpenSSLException
{
public:
    /**
     * Constructs a new OpenSSL exception.
     *
     * @param[in] msg the general cause of the exception.
     */
    explicit OpenSSLException(const std::string &msg);

    /**
     * Constructs a new OpenSSL exception.
     *
     * @param[in] msg the general cause of the exception.
     * @param[in] openssl_err the specific OpenSSL failure
     *            information.
     */
    OpenSSLException(const std::string &msg, const std::string &openssl_err);

    /** Destructor. */
    virtual ~OpenSSLException() {}

    /**
     * Create and throw an OpenSSL exception containing the last
     * OpenSSL error and stack. The OpenSSL error and stack is also
     * traced.
     *
     * @param[in] msg the general cause of the exception.
     * @param[in] file the filename.
     * @param[in] line the line number.
     * @param[in] function the function name.
     * @throw OpenSSLException.
     */
    static void throw_message(const char* msg, const char* file, int line,
                              const char* function, bool doAbort = true);

private:
    std::string openssl_err_; //!< OpenSSL error details.
};

}} // namespace cadmium::crypto

#endif // __OPENSSLEXCEPTION_H__
