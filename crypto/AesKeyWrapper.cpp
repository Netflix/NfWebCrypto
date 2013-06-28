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
#include "AesKeyWrapper.h"
#include <assert.h>
#include <openssl/aes.h>
#include <crypto/OpenSSLException.h>

namespace cadmium {
namespace crypto {

AesKeyWrapper::AesKeyWrapper(const Vuc& wrappingKey, const Vuc& initVal)
:   wrappingKey_(wrappingKey), initVal_(initVal)
{
    assert(!wrappingKey.empty());
}

AesKeyWrapper::~AesKeyWrapper()
{
}

bool AesKeyWrapper::wrap(const Vuc& keyToWrap, Vuc& wrappedKey)
{
//    int AES_set_encrypt_key(const unsigned char *userKey, const int bits,
//        AES_KEY *key);
//
//    int AES_wrap_key(AES_KEY *key, const unsigned char *iv,
//            unsigned char *out,
//            const unsigned char *in, unsigned int inlen)

    AES_KEY aes_key;
    int ret = AES_set_encrypt_key(&wrappingKey_[0], wrappingKey_.size() * 8, &aes_key);
    if (ret != 0)
    {
        OPENSSLERROR_MSG("AesKeyWrapper::wrap: AES_set_encrypt_key failed");
        return false;
    }

    const unsigned char *iv = NULL;
    if (initVal_.size())
        iv = &initVal_[0];
    const int wrappedKeySize(keyToWrap.size() + 8);
    wrappedKey.resize(wrappedKeySize);
    ret = AES_wrap_key(&aes_key, iv, &wrappedKey[0], &keyToWrap[0], keyToWrap.size());
    if (ret < 0 || ret != wrappedKeySize)
    {
        OPENSSLERROR_MSG("AesKeyWrapper::wrap: AES_wrap_key failed");
        return false;
    }

    Vuc(wrappedKey.begin(), wrappedKey.end()).swap(wrappedKey);

    return true;
}

bool AesKeyWrapper::unwrap(const Vuc& wrappedKey, Vuc& unwrappedKey)
{
    AES_KEY aes_key;
    int ret = AES_set_decrypt_key(&wrappingKey_[0], wrappingKey_.size() * 8, &aes_key);
    if (ret != 0)
    {
        OPENSSLERROR_MSG("AesKeyWrapper::wrap: AES_set_encrypt_key failed");
        return false;
    }

    const unsigned char *iv = NULL;
    if (initVal_.size())
        iv = &initVal_[0];
    const int unwrappedKeySize(wrappedKey.size() - 8);
    unwrappedKey.resize(unwrappedKeySize);
    ret = AES_unwrap_key(&aes_key, iv, &unwrappedKey[0], &wrappedKey[0], wrappedKey.size());
    if (ret < 0 || ret != unwrappedKeySize)
    {
        OPENSSLERROR_MSG("AesKeyWrapper::wrap: AES_wrap_key failed");
        return false;
    }

    Vuc(unwrappedKey.begin(), unwrappedKey.end()).swap(unwrappedKey);

    return true;
}


}} // namespace cadmium::crypto
