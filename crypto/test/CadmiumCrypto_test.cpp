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
#include <fstream>
#include <algorithm>
#include <iterator>
#include <gtest/gtest.h>
#include <crypto/CadmiumCrypto.h>
#include <base/Base64.h>

// FIXME: These tests are barely started. More comprehensive tests may be found
// at the javascript layer.

using namespace std;
using namespace cadmium;
using namespace cadmium::crypto;

namespace   // anonymous
{

inline CadmiumCrypto::Vuc str64toVuc(const string& dataStr64)
{
    const CadmiumCrypto::Vuc dataVec64(dataStr64.begin(), dataStr64.end());
    return CadmiumCrypto::Vuc(cadmium::base::Base64::decode(dataVec64));
}

inline string vucToStr64(const CadmiumCrypto::Vuc& dataVec)
{
    const CadmiumCrypto::Vuc dataVec64 = cadmium::base::Base64::encode(dataVec);
    return string(dataVec64.begin(), dataVec64.end());
}

}

class CadmiumCryptoTest : public ::testing::Test
{
protected:
    CadmiumCryptoTest()
    :   pCadmiumCrypto_(NULL)
    // Peter Stout gave me this key. It is for the MSL entity identified by the
    // RSA pubkeyid CRYPTEX_TEST_KEY_L that is currently being used by the NCCP
    // test server.
    ,   rsaPubKeyStr64_("MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCbLKhmDzDUbgBEBqUusAuB1itXjjH8iQWNnIFPDe/GMCTvii1Pl7yvQqU9LzU0Re2kK0AmWLYbgKpJkaYNQIbhhhlv3tV3wTCJGkAiRJkHvcvt8HOLuxa8JM69HdMg8HyIfuXCxy7AxwworSn63Gu5DKu7nhWJB83qXqYEO73JCQIDAQAB")
    ,   rawKeyStrHex_("6162636462636465636465666465666765666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f7071")
    {
    }

    virtual ~CadmiumCryptoTest()
    {
    }

    virtual void SetUp()
    {
        pCadmiumCrypto_ = new CadmiumCrypto();
        CadErr err = pCadmiumCrypto_->init(getRandSeedBytes());
        ASSERT_EQ(CAD_ERR_OK, err);
    }

    virtual void TearDown()
    {
        delete pCadmiumCrypto_;
    }

    CadmiumCrypto::Vuc getRandSeedBytes()
    {
        ifstream rndDev("/dev/urandom");
        // crappy ifstream does not work with an unsigned char buffer
        vector<char> randBytes(CadmiumCrypto::MIN_SEED_LEN);
        rndDev.read(&randBytes[0], CadmiumCrypto::MIN_SEED_LEN);
        return CadmiumCrypto::Vuc(randBytes.begin(), randBytes.end());
    }

    CadmiumCrypto::Vuc hexStrToVuc(const string& hexStr)
    {
        CadmiumCrypto::Vuc out;
        for (string::const_iterator it = hexStr.begin(); it != hexStr.end(); advance(it, 2))
        {
            unsigned int tmpUi;
            sscanf(string(it, it+2).c_str(), "%x", &tmpUi);
            out.push_back(static_cast<unsigned char>(tmpUi));
        }
        return out;
    }

protected:
    CadmiumCrypto * pCadmiumCrypto_;
    const string rsaPubKeyStr64_;
    const string rawKeyStrHex_;
};

TEST_F(CadmiumCryptoTest, TestInit)
{
    const auto_ptr<CadmiumCrypto> pCadmiumCrypto(new CadmiumCrypto());
    const CadmiumCrypto::Vuc shortSeed(CadmiumCrypto::MIN_SEED_LEN - 1, 0);
    ASSERT_EQ(CAD_ERR_BADARG, pCadmiumCrypto->init(shortSeed));
    ASSERT_EQ(CAD_ERR_OK, pCadmiumCrypto->init(getRandSeedBytes()));
    ASSERT_EQ(CAD_ERR_ALREADY_INITIALIZED, pCadmiumCrypto->init(getRandSeedBytes()));
}

TEST_F(CadmiumCryptoTest, TestImportKey)
{
//    /** Import a key
//     * This method imports a key into the local key store.
//     * @param format In. The format of the keyData containing the key
//     * @param keyData In. The data containing the key. In the case of RAW
//     *     format, this data is base64-encoded.
//     * @param algorithm In. The algorithm used to generate the key.
//     * @param extractable In. Whether or not the raw keying material may be
//     *     exported by the application.
//     * @param keyUsage In. A vector of KeyUsage, indicating what operations may
//     *     be used with this key.
//     * @param keyHandle Out. The handle of the imported key in the key store.
//     * @param keyType Out. The type of the key, deduced from format and keyData
//     */
//    enum KeyFormat
//    {
//        RAW,    //< An unformatted sequence of bytes. Intended for secret keys.
//        PKCS8,  //< The DER encoding of the PrivateKeyInfo structure from RFC 5208.
//        SPKI,   //< The DER encoding of the SubjectPublicKeyInfo structure from RFC 5280.
//        JWK     //< The key is represented as JSON according to the JSON Web Key format.
//    };
//    enum Algorithm
//    {
//        HMAC,
//        AES_CBC,
//        AES_GCM,
//        AES_CTR,
//        RSAES_PKCS1_V1_5,
//        RSASSA_PKCS1_V1_5
//    };
//    enum KeyType {SECRET, PUBLIC, PRIVATE};
//    enum KeyUsage {ENCRYPT, DECRYPT, SIGN, VERIFY, DERIVE};
//    CadErr importKey(KeyFormat format, const std::string& keyData,
//        Algorithm algorithm, bool extractable, const std::vector<KeyUsage> keyUsage,
//        uint32_t& keyHandle, KeyType& keyType);

    const CadmiumCrypto::Vuc rawKeyData(hexStrToVuc(rawKeyStrHex_));
    const CadmiumCrypto::KeyUsage ku[2] = {CadmiumCrypto::ENCRYPT, CadmiumCrypto::DECRYPT};
    const vector<CadmiumCrypto::KeyUsage> keyUsage(&ku[0], &ku[0]+2);
    const CadmiumCrypto::KeyUsage ku1[2] = {CadmiumCrypto::SIGN, CadmiumCrypto::VERIFY};
    const vector<CadmiumCrypto::KeyUsage> keyUsage1(&ku1[0], &ku1[0]+2);
    uint32_t keyHandle = 999;
    CadmiumCrypto::KeyType keyType = CadmiumCrypto::PUBLIC;
    CadErr err;

    // Negative Test: empty keyData
    ASSERT_EQ(CAD_ERR_BADENCODING, pCadmiumCrypto_->importKey(CadmiumCrypto::RAW, string(), CadmiumCrypto::AES_CBC, false, keyUsage, keyHandle, keyType));

    // Negative Test: bad base64 encoding of keyData
    ASSERT_EQ(CAD_ERR_BADENCODING, pCadmiumCrypto_->importKey(CadmiumCrypto::RAW, "!@#$%", CadmiumCrypto::AES_CBC, false, keyUsage, keyHandle, keyType));

    // Negative tests: incompatible algorithm vs format
    // algorithm = "HMAC", "AES-CBC", "AES-GCM", "AES-CTR" require format = RAW
    const string rawKeyDataStr64(vucToStr64(rawKeyData));
    ASSERT_EQ(CAD_ERR_UNSUPPORTED_KEY_ENCODING, pCadmiumCrypto_->importKey(CadmiumCrypto::SPKI, rawKeyDataStr64, CadmiumCrypto::HMAC,    false, keyUsage1, keyHandle, keyType));
    ASSERT_EQ(CAD_ERR_UNSUPPORTED_KEY_ENCODING, pCadmiumCrypto_->importKey(CadmiumCrypto::SPKI, rawKeyDataStr64, CadmiumCrypto::AES_CBC, false, keyUsage, keyHandle, keyType));
    ASSERT_EQ(CAD_ERR_UNSUPPORTED_KEY_ENCODING, pCadmiumCrypto_->importKey(CadmiumCrypto::SPKI, rawKeyDataStr64, CadmiumCrypto::AES_GCM, false, keyUsage, keyHandle, keyType));
    ASSERT_EQ(CAD_ERR_UNSUPPORTED_KEY_ENCODING, pCadmiumCrypto_->importKey(CadmiumCrypto::SPKI, rawKeyDataStr64, CadmiumCrypto::AES_CTR, false, keyUsage, keyHandle, keyType));
    // algorithm = "RSASSA-PKCS1-v1_5", "RSAES-PKCS1-v1_5" require format = SPKI or JWK
    ASSERT_EQ(CAD_ERR_UNSUPPORTED_KEY_ENCODING, pCadmiumCrypto_->importKey(CadmiumCrypto::RAW, rawKeyDataStr64, CadmiumCrypto::RSASSA_PKCS1_V1_5, false, keyUsage1, keyHandle, keyType));
    ASSERT_EQ(CAD_ERR_UNSUPPORTED_KEY_ENCODING, pCadmiumCrypto_->importKey(CadmiumCrypto::RAW, rawKeyDataStr64, CadmiumCrypto::RSAES_PKCS1_V1_5,  false, keyUsage, keyHandle, keyType));

    // All the negative tests should result in keyHandle set to 0 (invalid)
    ASSERT_EQ(keyHandle, (uint32_t)0);

    // Successfully import RAW AES key
    err = pCadmiumCrypto_->importKey(CadmiumCrypto::RAW, rawKeyDataStr64, CadmiumCrypto::AES_GCM, false, keyUsage, keyHandle, keyType);
    ASSERT_EQ(CAD_ERR_OK, err);
    ASSERT_NE((uint32_t)0, keyHandle);
    ASSERT_EQ(CadmiumCrypto::SECRET, keyType);

    // Check
    CadmiumCrypto::KeyType typeOut;
    bool extractableOut;
    CadmiumCrypto::Algorithm algorithmOut;
    vector<CadmiumCrypto::KeyUsage> usageOut;
    err = pCadmiumCrypto_->getKeyInfo(keyHandle, typeOut, extractableOut, algorithmOut, usageOut);
    ASSERT_EQ(keyType, typeOut);
    ASSERT_FALSE(extractableOut);
    ASSERT_EQ(CadmiumCrypto::AES_GCM, algorithmOut);
    ASSERT_EQ(keyUsage, usageOut);

    // Successfully import SPKI RSA key
    err = pCadmiumCrypto_->importKey(CadmiumCrypto::SPKI, rsaPubKeyStr64_, CadmiumCrypto::RSAES_PKCS1_V1_5, true, keyUsage, keyHandle, keyType);
    ASSERT_EQ(CAD_ERR_OK, err);
    ASSERT_NE((uint32_t)0, keyHandle);
    ASSERT_EQ(CadmiumCrypto::PUBLIC, keyType);

    // Check
    err = pCadmiumCrypto_->getKeyInfo(keyHandle, typeOut, extractableOut, algorithmOut, usageOut);
    ASSERT_EQ(keyType, typeOut);
    ASSERT_TRUE(extractableOut);
    ASSERT_EQ(CadmiumCrypto::RSAES_PKCS1_V1_5, algorithmOut);
    ASSERT_EQ(keyUsage, usageOut);

    // TODO import JWK RSA key
}

TEST_F(CadmiumCryptoTest, TestExportKey)
{
//    /** Export a key
//     * This method exports a key from the local key store. Only keys that are
//     * marked extractable may be exported.
//     * @param keyHandle In. The handle of the key to export.
//     * @param format In. The desired format of the exported key data.
//     * @param keyData Out. The data containing the key in the desired format. In
//     *     the case of RAW or SPKI format, this data is base64-encoded.
//     */
//    CadErr exportKey(uint32_t keyHandle, KeyFormat format, std::string& keyData);

    const CadmiumCrypto::KeyUsage ku[1] = {CadmiumCrypto::DECRYPT};
    const vector<CadmiumCrypto::KeyUsage> keyUsage(&ku[0], &ku[0]+1);
    uint32_t keyHandle1 = 999;
    uint32_t keyHandle2;
    uint32_t keyHandle3;
    CadmiumCrypto::KeyType keyType = CadmiumCrypto::PUBLIC;
    CadErr err;
    string keyDataStr64;

    // Import good keys
    // Key 1: Extractable RSA public key
    err = pCadmiumCrypto_->importKey(CadmiumCrypto::SPKI, rsaPubKeyStr64_, CadmiumCrypto::RSAES_PKCS1_V1_5, true, keyUsage, keyHandle1, keyType);
    ASSERT_EQ(CAD_ERR_OK, err);
    ASSERT_NE((uint32_t)0, keyHandle1);
    ASSERT_EQ(CadmiumCrypto::PUBLIC, keyType);
    // Key 2: Non-Extractable RSA public key, should be forced extractable
    err = pCadmiumCrypto_->importKey(CadmiumCrypto::SPKI, rsaPubKeyStr64_, CadmiumCrypto::RSAES_PKCS1_V1_5, false, keyUsage, keyHandle2, keyType);
    ASSERT_EQ(CAD_ERR_OK, err);
    ASSERT_NE((uint32_t)0, keyHandle1);
    ASSERT_EQ(CadmiumCrypto::PUBLIC, keyType);
    // Key 3: Extractable RAW private key
    const string rawKeyDataStr64(vucToStr64(hexStrToVuc(rawKeyStrHex_)));
    err = pCadmiumCrypto_->importKey(CadmiumCrypto::RAW, rawKeyDataStr64, CadmiumCrypto::AES_CBC, true, keyUsage, keyHandle3, keyType);
    ASSERT_EQ(CAD_ERR_OK, err);
    ASSERT_NE((uint32_t)0, keyHandle3);
    ASSERT_EQ(CadmiumCrypto::SECRET, keyType);

    // Negative Test: bad key handle
    ASSERT_EQ(CAD_ERR_BADKEYINDEX, pCadmiumCrypto_->exportKey(555, CadmiumCrypto::SPKI, keyDataStr64));

    // Key 1 Successful JWK export
    ASSERT_EQ(CAD_ERR_OK, pCadmiumCrypto_->exportKey(keyHandle1, CadmiumCrypto::JWK, keyDataStr64));

    // Key 1 Successful export
    err = pCadmiumCrypto_->exportKey(keyHandle1, CadmiumCrypto::SPKI, keyDataStr64);
    ASSERT_EQ(CAD_ERR_OK, err);
    ASSERT_STREQ(rsaPubKeyStr64_.c_str(), keyDataStr64.c_str());

    // Key 2 Successful export
    err = pCadmiumCrypto_->exportKey(keyHandle2, CadmiumCrypto::SPKI, keyDataStr64);
    ASSERT_EQ(CAD_ERR_OK, err);
    ASSERT_STREQ(rsaPubKeyStr64_.c_str(), keyDataStr64.c_str());

    // Key 3 Negative Test: non-RSA key (for now only RSA keys are exportable)
    ASSERT_EQ(CAD_ERR_BADKEYNAME, pCadmiumCrypto_->exportKey(keyHandle3, CadmiumCrypto::SPKI, keyDataStr64));
}
