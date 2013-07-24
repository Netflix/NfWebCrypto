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
#include "AesGcmCipher.h"
#include <assert.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <base/DebugUtil.h>
#include <crypto/OpenSSLException.h>
#include <crypto/ScopedOpenSSL.h>

// TODO: Look into the new CRYPTO_gcm128_* OpenSSL routines that appeared in
// 1.0.1c. Much cleaner interface!

namespace cadmium {
namespace crypto {

namespace   // anonymous
{

void sizeOutput(size_t inSize, AesGcmCipher::Vuc& outVuc)
{
    // size the output buffer
    // according to the openssl docs:
    // the amount of data written may be as large as (in.size() + cipher_block_size - 1)
    size_t outSize = inSize + AES_BLOCK_SIZE - 1;
    // the output buffer must also be a multiple of blocksize
    if ((outSize % AES_BLOCK_SIZE) != 0)
        outSize = ((outSize / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;
    outVuc.resize(outSize, 0);
}

}   // anonymous namespace

AesGcmCipher::AesGcmCipher(const Vuc& key, const Vuc& iv)
:   key_(key)
,   iv_(iv)
,   keyLength_(static_cast<KeyLength>(key.size()))
{
    assert(!key_.empty());
    assert(keyLength_==KL128 || keyLength_==KL192 || keyLength_==KL256);
    assert(!iv_.empty());
}

AesGcmCipher::~AesGcmCipher()
{
}

bool AesGcmCipher::encrypt(const Vuc& clearText, const Vuc& aad, Vuc& cipherText,
        Vuc& mac)
{
    // create the cipher context; ScopedOpenSSL ensures deletion on scope exit
    ScopedOpenSSL<EVP_CIPHER_CTX, EVP_CIPHER_CTX_free> pCtx(EVP_CIPHER_CTX_new());

    // set cipher
    int ret = EVP_EncryptInit(pCtx.get(), getCipher(), NULL, NULL);
    if (!ret)
    {
        OPENSSLERROR_MSG("AesGcmCipher::encrypt: EVP_DecryptInit fail setting cipher");
        return false;
    }

    // set iv length
    ret = EVP_CIPHER_CTX_ctrl(pCtx.get(), EVP_CTRL_GCM_SET_IVLEN, iv_.size(), NULL);
    if (!ret)
    {
        OPENSSLERROR_MSG("AesGcmCipher::decrypt: EVP_CIPHER_CTX_ctrl EVP_CTRL_GCM_SET_IVLEN fail");
        return false;
    }

    // set key and iv
    ret = EVP_EncryptInit(pCtx.get(), NULL, &key_[0], &iv_[0]);
    if (!ret)
    {
        OPENSSLERROR_MSG("AesGcmCipher::decrypt: EVP_DecryptInit fail setting key/iv");
        return false;
    }

    // add Additional Authenticated Data (AAD)
    int nBytes = 0;
    ret = EVP_EncryptUpdate(pCtx.get(), NULL, &nBytes, &aad[0], aad.size());
    if (!ret)
    {
        OPENSSLERROR_MSG("AesGcmCipher::decrypt: EVP_DecryptUpdate fail when setting AAD");
        return false;
    }

    // size the output buffer
    sizeOutput(clearText.size(), cipherText);

    // do the encrypt
    nBytes = 0;
    ret = EVP_EncryptUpdate(pCtx.get(), &cipherText[0], &nBytes, &clearText[0], clearText.size());
    if (!ret)
    {
        OPENSSLERROR_MSG("AesGcmCipher::encrypt: EVP_DecryptUpdate fail during encrypt");
        return false;
    }
    DLOG() << "AesGcmCipher::encrypt: EVP_EncryptUpdate " << clearText.size() <<
            " bytes in, " << nBytes << " bytes out\n";

    // finalization
    int nTotalBytes = nBytes;
    ret = EVP_EncryptFinal(pCtx.get(), &cipherText[0], &nBytes);
    if (!ret)
    {
        OPENSSLERROR_MSG("AesGcmCipher::encrypt: EVP_EncryptFinal fail");
        return false;
    }
    nTotalBytes += nBytes;  // the actual clearText size is in nTotalBytes
    assert(nTotalBytes);
    Vuc(cipherText.begin(), cipherText.begin()+nTotalBytes).swap(cipherText); // shrink to fit

    // get the tag (MAC)
    const int TAG_LENGTH = 16;  // always want a 128-bit tag
    mac.resize(TAG_LENGTH);
    ret = EVP_CIPHER_CTX_ctrl(pCtx.get(), EVP_CTRL_GCM_GET_TAG, TAG_LENGTH, &mac[0]);
    if (!ret)
    {
        OPENSSLERROR_MSG("AesGcmCipher::encrypt: EVP_CIPHER_CTX_ctrl fail while getting tag");
        return false;
    }
    Vuc(mac.begin(), mac.end()).swap(mac); // shrink to fit

    return true;
}

bool AesGcmCipher::decrypt(const Vuc& cipherText, const Vuc& aad, const Vuc& mac,
        Vuc& clearText)
{
    assert(!mac.empty());

    // create the cipher context; ScopedOpenSSL ensures deletion on scope exit
    ScopedOpenSSL<EVP_CIPHER_CTX, EVP_CIPHER_CTX_free> pCtx(EVP_CIPHER_CTX_new());

    // set cipher
    int ret = EVP_DecryptInit(pCtx.get(), getCipher(), NULL, NULL);
    if (!ret)
    {
        OPENSSLERROR_MSG("AesGcmCipher::decrypt: EVP_DecryptInit fail setting cipher");
        return false;
    }

    // set iv length
    ret = EVP_CIPHER_CTX_ctrl(pCtx.get(), EVP_CTRL_GCM_SET_IVLEN, iv_.size(), NULL);
    if (!ret)
    {
        OPENSSLERROR_MSG("AesGcmCipher::decrypt: EVP_CIPHER_CTX_ctrl EVP_CTRL_GCM_SET_IVLEN fail");
        return false;
    }

    // set key and iv
    ret = EVP_DecryptInit(pCtx.get(), NULL, &key_[0], &iv_[0]);
    if (!ret)
    {
        OPENSSLERROR_MSG("AesGcmCipher::decrypt: EVP_DecryptInit fail setting key/iv");
        return false;
    }

    // set authentication tag (MAC)
    ret = EVP_CIPHER_CTX_ctrl(pCtx.get(), EVP_CTRL_GCM_SET_TAG, mac.size(), (void*)&mac[0]);
    if (!ret)
    {
        OPENSSLERROR_MSG("AesGcmCipher::decrypt: EVP_CIPHER_CTX_ctrl EVP_CTRL_GCM_SET_TAG fail");
        return false;
    }

    // add Additional Authenticated Data (AAD)
    int nBytes = 0;
    ret = EVP_DecryptUpdate(pCtx.get(), NULL, &nBytes, &aad[0], aad.size());
    if (!ret)
    {
        OPENSSLERROR_MSG("AesGcmCipher::decrypt: EVP_DecryptUpdate fail when setting AAD");
        return false;
    }

    // size the output buffer; do not put result in output until auth passes
    Vuc localClearText;
    sizeOutput(cipherText.size(), localClearText);

    // do the decrypt now
    nBytes = 0;
    ret = EVP_DecryptUpdate(pCtx.get(), &localClearText[0], &nBytes, &cipherText[0], cipherText.size());
    if (!ret)
    {
        OPENSSLERROR_MSG("AesGcmCipher::decrypt: EVP_DecryptUpdate fail during decrypt");
        return false;
    }
    DLOG() << "AesGcmCipher::decrypt: EVP_DecryptUpdate " << cipherText.size() <<
            " bytes in, " << nBytes << " bytes out\n";

    // finalization and authentication; if ret != 1 authentication failed
    int nTotalBytes = nBytes;
    ret = EVP_DecryptFinal(pCtx.get(), &localClearText[0], &nBytes);
    if (!ret)
    {
        DLOG() << "AesGcmCipher::decrypt: authentication failed\n";
        return false;
    }
    nTotalBytes += nBytes;

    // the actual clearText size is in nTotalBytes
    assert(nTotalBytes);
    Vuc(localClearText.begin(), localClearText.begin()+nTotalBytes).swap(clearText); // shrink to fit
    return true;
}

const EVP_CIPHER* AesGcmCipher::getCipher() const
{
    const EVP_CIPHER* cipher = NULL;
    DLOG() << "AesGcmCipher::getCipher: keyLen = ";
    switch (keyLength_)
    {
        case KL128: DLOG() << "128\n"; cipher = EVP_aes_128_gcm(); break;
        case KL192: DLOG() << "192\n"; cipher = EVP_aes_192_gcm(); break;
        case KL256: DLOG() << "256\n"; cipher = EVP_aes_256_gcm(); break;
        default:    assert(false);                                 break;
    }
    return cipher;
}

}}   // namespace cadmium::crypto
