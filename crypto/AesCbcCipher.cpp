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
#include "AesCbcCipher.h"
#include <stddef.h>
#include <assert.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <crypto/ScopedOpenSSL.h>

namespace cadmium {
namespace crypto {

AesCbcCipher::AesCbcCipher(const Vuc& key, const Vuc& iv)
:   key_(key)
,   iv_(iv)
,   keyLength_(static_cast<KeyLength>(key.size()))
{
    assert(!key_.empty());
    assert(keyLength_==KL128 || keyLength_==KL192 || keyLength_==KL256);
    assert(!iv_.empty());
}

AesCbcCipher::~AesCbcCipher()
{
}

bool AesCbcCipher::encrypt(const Vuc& in, Vuc& out)
{
    // according to the openssl docs:
    // the amount of data written may be as large as (in.size() + cipher_block_size - 1)
    size_t outSize = in.size() + AES_BLOCK_SIZE - 1;
    // the output buffer must also be a multiple of blocksize
    if ((outSize % AES_BLOCK_SIZE) != 0)
        outSize = ((outSize / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;
    out.resize(outSize, 0);

    // init encryption
    ScopedOpenSSL<EVP_CIPHER_CTX, EVP_CIPHER_CTX_free> ctx(EVP_CIPHER_CTX_new());
    EVP_EncryptInit(ctx.get(), getCipher(), &key_[0], &iv_[0]);

    // do the encrypt; must keep track of the number of bytes produced
    int nBytes = 0;
    EVP_EncryptUpdate(ctx.get(), &out[0], &nBytes, &in[0], in.size());
    int nTotalBytes = nBytes;
    EVP_EncryptFinal(ctx.get(), &out[nBytes], &nBytes);
    nTotalBytes += nBytes;

    // the actual output size is in nTotalBytes
    assert(nTotalBytes);
    Vuc(out.begin(), out.begin()+nTotalBytes).swap(out); // shrink to fit
    return true;
}

bool AesCbcCipher::decrypt(const Vuc& in, Vuc& out)
{
    // according to the openssl docs:
    // the amount of data written may be as large as (in.size() + cipher_block_size - 1)
    size_t outSize = in.size() + AES_BLOCK_SIZE - 1;
    // the output buffer must also be a multiple of blocksize
    if ((outSize % AES_BLOCK_SIZE) != 0)
        outSize = ((outSize / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;
    out.resize(outSize, 0);

    // init the cipher; must keep track of the number of bytes produced
    ScopedOpenSSL<EVP_CIPHER_CTX, EVP_CIPHER_CTX_free> ctx(EVP_CIPHER_CTX_new());
    EVP_DecryptInit(ctx.get(), getCipher(), &key_[0], &iv_[0]);

    // do the decrypt
    int nBytes = 0;
    EVP_DecryptUpdate(ctx.get(), &out[0], &nBytes, &in[0], in.size());
    int nTotalBytes = nBytes;
    if (!EVP_DecryptFinal(ctx.get(), &out[nBytes], &nBytes))
        return false;   // padding incorrect
    nTotalBytes += nBytes;

    // the actual output size is in nTotalBytes
    assert(nTotalBytes);
    Vuc(out.begin(), out.begin()+nTotalBytes).swap(out); // shrink to fit
    return true;
}

const EVP_CIPHER* AesCbcCipher::getCipher() const
{
    const EVP_CIPHER* cipher = NULL;
    switch (keyLength_)
    {
        case KL128: cipher = EVP_aes_128_cbc(); break;
        case KL192: cipher = EVP_aes_192_cbc(); break;
        case KL256: cipher = EVP_aes_256_cbc(); break;
        default:    assert(false);              break;
    }
    return cipher;
}

}} // namespace cadmium::crypto
