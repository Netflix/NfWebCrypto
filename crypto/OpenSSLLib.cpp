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
#include <ostream>
#include <sstream>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/asn1.h>
#include <openssl/rand.h>
#include <openssl/objects.h>
#include <openssl/crypto.h>
#include <base/tr1.h>
#include <base/Mutex.h>
#include <base/SimpleThread.h>
#include <base/DebugUtil.h>
#include "OpenSSLLib.h"

namespace cadmium {
namespace crypto {

namespace {

#ifndef NF_NO_SSL_THREAD_CALLBACKS

// thread safety mutexes
cadmium::base::Mutex **mutex_array = NULL;

// thread safety callbacks

//static unsigned long id_func(); // for old OpenSSL 0.9.8
// Deprecated thread ID function for OpenSSL 0.9.8
//static unsigned long id_func(void)
//{
//    return ((unsigned long)cadmium::base::SimpleThread::selfId());
//}

void threadid_func(CRYPTO_THREADID *threadId)
{
    CRYPTO_THREADID_set_numeric(threadId, (unsigned long)cadmium::base::SimpleThread::selfId());
}

static void lock_func(int mode, int n, const char *, int)
{
    if (!mutex_array)
    {
        DLOG() << "uninitialized mutex array\n";
        return;
    }

    /* check CRYPTO_LOCK flag */
    if (mode & CRYPTO_LOCK)
        mutex_array[n]->lock();
    else
        mutex_array[n]->unlock();
}
#endif

}   // namespace anonymous

// note: no thread safety on setting init() / shutdown()
bool OpenSSLLib::init_ssl_ = false;
bool OpenSSLLib::init_crypto_ = false;
int OpenSSLLib::hostnameIndex_ = -1;

void OpenSSLLib::setInit(bool initialized)
{
    //Random::init_ = initialized;
}

bool OpenSSLLib::init(const unsigned char* random, uint32_t length)
{
#if 0
    bool success = init_crypto(random, length);
    if (!success)
        return false;
    return init_ssl();
#else
    return init_crypto(random, length);
#endif
}

bool OpenSSLLib::init(const std::vector<unsigned char> random)
{
    return OpenSSLLib::init(&random[0], random.size());
}

bool OpenSSLLib::init_crypto(const std::vector<unsigned char> random)
{
    return init_crypto(&random[0], random.size());
}

bool OpenSSLLib::init_crypto(const unsigned char* random, uint32_t length)
{
    if (init_crypto_)
    {
        //DLOG() << "OpenSSLLib::init_crypto() called more than once\n";
        return true;;
    }

    // init multi-thread support
    bool success = thread_init();
    if (!success)
        return false;

#ifdef BUILD_DEBUG
    // load error strings for libcrypto
    ERR_load_crypto_strings();
#endif

    // init RNG
    success = random_init(random, length);
    if (!success)
        return false;

    // add all algorithms
#ifndef NF_NO_SSL_INIT
    //OpenSSL_add_all_algorithms();
    // Add only the stuff we will be using
    EVP_add_cipher(EVP_aes_128_cbc());
    EVP_add_digest(EVP_sha1());
    EVP_add_digest(EVP_sha256());
    EVP_add_digest(EVP_sha384());
#endif

    // Set init flag and return success.
    init_crypto_ = true;
    return true;
}

#if 0
bool OpenSSLLib::init_ssl()
{
    if (init_ssl_)
    {
        DLOG() << "OpenSSLLib::init_ssl() called more than once\n";
    }
    if (!init_crypto_)
    {
        DLOG() << "OpenSSLLib::init_ssl() called without first "
               "calling OpenSSLLib::init_crypto()\n";
        return false;
    }

#ifdef BUILD_DEBUG
    // load error strings for libssl
    SSL_load_error_strings();
#endif

#ifndef NF_NO_SSL_INIT
    // init SSL library
    SSL_library_init();
#endif

    // grab some private storage for hostname verification
    OpenSSLLib::hostnameIndex_ = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);

    // Set init flag and return success.
    init_ssl_ = true;
    return true;
}
#endif

void OpenSSLLib::cleanup()
{
    cleanup_ssl();
    cleanup_crypto();
}

void OpenSSLLib::cleanup_ssl()
{
    init_ssl_ = false;
}

bool OpenSSLLib::cleanup_crypto()
{
    if (init_ssl_)
    {
        DLOG() << "OpenSSLLib::cleanup_crypto() called without "
               "first calling OpenSSLLib::cleanup_ssl()\n";
        return false;;
    }

    thread_cleanup();
    // delete ciphers & hash algos from openssl
    EVP_cleanup();
    // delete debug strings, if loaded
    ERR_free_strings();
    init_crypto_ = false;
    return true;
}

void OpenSSLLib::add_entropy(const unsigned char* random, uint32_t length,
                             double entropy)
{
    RAND_add(random, length, entropy);
}

void OpenSSLLib::add_entropy(std::vector<unsigned char> random, double entropy)
{
    OpenSSLLib::add_entropy(&random[0], random.size(), entropy);
}

int OpenSSLLib::hmacSha1(const std::string &key, const std::string &message, unsigned char *md)
{
    // duplicated in NBPApplication.cpp
    unsigned int count = 0;
    (void)HMAC(EVP_sha1(), reinterpret_cast<const void *>(key.data()), key.size(),
               reinterpret_cast<const unsigned char*>(message.data()), message.size(),
               md, &count);
    return count;
}

bool OpenSSLLib::certificatesFromPem(const void *pem, int length, std::vector<void*> *certificates, CertType type)
{
    if (!pem || length <= 0 || !certificates)
        return true;

    BIO *in = BIO_new_mem_buf(const_cast<void*>(pem), length);
    if (!in)
        return false;

    do {
        void *x = 0;
        if(type == CertType_X509)
            x = PEM_read_bio_X509(in, 0, 0, 0);
        else if(type == CertType_PrivateKey)
            x = PEM_read_bio_PrivateKey(in, 0, 0, 0);
        if (!x)
            break;
        certificates->push_back(x);
    } while (true);

    BIO_free(in);
    return true;
}

void OpenSSLLib::freeCertificate(void *cert, CertType type)
{
    if(type == CertType_X509)
        X509_free(reinterpret_cast<X509*>(cert));
    else if(type == CertType_PrivateKey)
        EVP_PKEY_free(reinterpret_cast<EVP_PKEY*>(cert));
}

bool OpenSSLLib::random_init(const unsigned char* random, uint32_t length)
{
    if (length < MIN_SEED_LEN)
    {
        DLOG() << "random seed size (" << length << ") < " << MIN_SEED_LEN << std::endl;
        return false;
    }
    RAND_seed(random, length);
    // also set Random.init_ so that users of that class can test for
    // RNG initialization
    //Random::init_ = true;
    return true;
}

bool OpenSSLLib::thread_init()
{
#ifndef NF_NO_SSL_THREAD_CALLBACKS
    if (mutex_array)
    {
        DLOG() << "thread_init() called more than once\n";
        return false;;
    }

    mutex_array = (cadmium::base::Mutex **)malloc(
        CRYPTO_num_locks() * sizeof(cadmium::base::Mutex *));
    for (int i=0; i<CRYPTO_num_locks(); ++i)
        mutex_array[i] = new cadmium::base::Mutex();

    /* set threading callbacks */
    //CRYPTO_set_id_callback(id_func);  // for old OpenSSL 0.9.8
    CRYPTO_THREADID_set_callback(threadid_func);
    CRYPTO_set_locking_callback(lock_func);
#endif
    return true;
}

void OpenSSLLib::thread_cleanup()
{
#ifndef NF_NO_SSL_THREAD_CALLBACKS
    if (mutex_array)
    {
        /* unset callbacks */
        CRYPTO_set_id_callback(NULL);
        CRYPTO_set_locking_callback(NULL);

        /* delete mutex_array */
        for (int i=0; i<CRYPTO_num_locks(); ++i)
            delete mutex_array[i];
        free(mutex_array);

        mutex_array = NULL;
    }
#endif
}

}} // namespace cadmium::crypto
