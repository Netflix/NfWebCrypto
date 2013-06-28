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
#ifndef OPENSSLLIB_H
#define OPENSSLLIB_H

/**
 * @file OpenSSLLib.h OpenSSL initialization and cleanup.
 *
 * This class provides methods to manage OpenSSL. If you manage
 * OpenSSL separately, you must still use this class to notify the NRD
 * library of the OpenSSL state.
 */

#include <string>
#include <vector>
#include <stdint.h>
#include <openssl/asn1.h>
#include <openssl/evp.h>

namespace cadmium {
namespace crypto {

/**
 * @class OpenSSLLib OpenSSLLib.hpp
 * @brief OpenSSL library (libcrypto) initialization and cleanup
 *        routines.
 *
 * This class must be used to either initialize and cleanup the
 * OpenSSL library or to notify the NRD library if OpenSSL is
 * initialized or no longer initialized.
 *
 * To use this library to manage OpenSSL, use one of the
 * init(const unsigned char*, uint32_t) or
 * init(const std::vector<unsigned char>) methods and the cleanup()
 * method.
 *
 * If you manage OpenSSL separately, call setInit(bool) to set the
 * OpenSSL initialization state.
 */
class OpenSSLLib {
public:
    /** Minimum size of random seed needed to initialize OpenSSL. */
    static const size_t MIN_SEED_LEN = 512 / 8;

    /**
     * If you do not use this class to initialize and cleanup the
     * OpenSSL subsystem for your application, use this method to
     * inform OpenSSLLib of OpenSSL's state.
     *
     * Call with initialized true after OpenSSL has been
     * initialized. Call with initialized false before OpenSSL is
     * cleaned up.
     *
     * Do not call any other functions on this class if you intend to
     * use this method.
     *
     * @param[in] initialized true if OpenSSL is initialized, false if
     *            it is not.
     */
    static void setInit(bool initialized);

    /**
     * Initialize all components of the OpenSSL library. This calls
     * init_crypto() followed by init_ssl().
     *
     * @param[in] random seed for RNG, must be >= MIN_SEED_LEN in
     *            size.
     * @param[in] length of random seed.
     * @return true if successful;
     *         false if the seed is too short;
     *         false if already initialized.
     * @sa OpenSSL::init(const std::vector<unsigned char>)
     */
    static bool init(const unsigned char* random, uint32_t length);

    /**
     * Initialize OpenSSL. This calls init_crypto() followed by
     * init_ssl().
     *
     * @param[in] random seed for RNG, must be >= MIN_SEED_LEN in
     *            size.
     * @return true if successful;
     *         false if the seed is too short;
     *         false if already initialized.
     * @sa OpenSSLLib::init(const unsigned char* const, uint32)
     */
    static bool init(const std::vector<unsigned char> random);

    /**
     * Initialize the crypto portion (libcrypto) of the OpenSSL
     * library.
     *
     * @param[in] random seed for RNG, must be >= MIN_SEED_LEN in
     *            size.
     * @param[in] length of random seed.
     * @return true if successful;
     *         false if the seed is too short;
     *         false if already initialized.
     */
    static bool init_crypto(const unsigned char* random, uint32_t length);

    /**
     * Initialize the crypto portion (libcrypto) of the OpenSSL
     * library.
     *
     * @param[in] random seed for RNG, must be >= MIN_SEED_LEN in
     *            size.
     * @return true if successful;
     *         false if the seed is too short;
     *         false if already initialized.
     */
    static bool init_crypto(const std::vector<unsigned char> random);

    /**
     * Initialize the SSL portion (libssl) of the OpenSSL library.
     *
     * Note: init_crypto() must be called before init_ssl().
     *
     * @return false if called more than once;
     *         false if init_crypto() has not been
     *         called.
     */
    static bool init_ssl();

    /**
     * Cleanup OpenSSL when shutting down. This calls cleanup_ssl()
     * followed by cleanup_crypto().
     */
    static void cleanup();

    /**
     * Clean up the SSL portion (libssl) of the OpenSSL library.
     */
    static void cleanup_ssl();

    /**
     * Clean up the crypto portion (libcrypto) of the OpenSSL library.
     *
     * Note: cleanup_ssl() must be called before cleanup_crypto().
     *
     * @return false if cleanup_ssl() has not
     *         been called.
     */
    static bool cleanup_crypto();

    /**
     * Add some additional entropy to the RNG.
     *
     * @param[in] random data for RNG.
     * @param[in] length of data.
     * @param[in] entropy lower-bound of data entropy (see RFC
     *            1750). This is equal to the data length if the data
     *            is pulled from /dev/random.
     */
    static void add_entropy(const unsigned char* random, uint32_t length,
                            double entropy);

    /**
     * Add some additional entropy to the RNG.
     *
     * @param[in] random data for RNG.
     * @param[in] entropy lower-bound of data entropy (see RFC
     *            1750). This is equal to the data length if the data
     *            is pulled from /dev/random.
     */
    static void add_entropy(std::vector<unsigned char> random,
                            double entropy);

    /**
     * Returns a private data index where the remote hostname can be
     * stored. The value can be set using SSL_set_ex_data() and
     * retrieved using SSL_get_ex_data().
     *
     * @return a private data index for remote hostname storage.
     */
    static int hostnameIndex() { return hostnameIndex_; }

    static int hmacSha1(const std::string &key, const std::string &message, unsigned char *md);

    enum CertType {
        CertType_X509,
        CertType_PrivateKey
    };
    static bool certificatesFromPem(const void *data, int len, std::vector<void*> *certificates, CertType type=CertType_X509);
    static void freeCertificate(void *certificate, CertType type=CertType_X509);
private:
    /**
     * Initializes the random number generator using the provided
     * seed.
     *
     * @param[in] random seed for RNG, must be >= MIN_SEED_LEN in
     *            size.
     * @param[in] length of random seed.
     * @return true if successful;
     *         false if the random seed is too short.
     */
    static bool random_init(const unsigned char* random, uint32_t length);

    /**
     * Initializes OpenSSL for use with threads.
     *
     * @return false if called more than once.
     */
    static bool thread_init();

    /**
     * Cleans up thread callbacks and mutexes.
     */
    static void thread_cleanup();

    static bool init_ssl_;     //!< True if libssl initialized.
    static bool init_crypto_;  //!< True if libcrypto initialized.
    static int hostnameIndex_; //!< Private data storage index.
};

}} // namespace cadmium::crypto

#endif
