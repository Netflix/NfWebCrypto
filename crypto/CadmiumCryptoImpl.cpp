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
#include "CadmiumCryptoImpl.h"
#include <assert.h>
#include <set>
#include <algorithm>
#include <base/Base64.h>
#include <base/DebugUtil.h>
#include <base/IDeviceInfo.h>
#include <crypto/OpenSSLLib.h>
#include <crypto/NtbaUtil.h>
#include <crypto/HMAC.h>
#include <crypto/Random.h>
#include <crypto/DigestAlgo.h>
#include <crypto/Digester.h>
#include <crypto/AesCbcCipher.h>
#include <crypto/AesGcmCipher.h>
#include <crypto/CadmiumCrypto.h>
#include <crypto/RsaContext.h>
#include <crypto/DiffieHellmanContext.h>
#include <crypto/AesKeyWrapper.h>
#include <crypto/Pbkdf2.h>
#include "SampleKeyProvision.h"

using namespace std;
using std::tr1::shared_ptr;
using namespace cadmium::base;

namespace cadmium {
namespace crypto {

typedef CadmiumCrypto::Vuc Vuc;

extern unsigned char gRandTable[];

namespace   // anonymous
{

#define xstr(s) str(s)
#define str(s) #s

#ifndef SECRET_SYSTEM_KEY
#error "SECRET_SYSTEM_KEY must be defined"
#else
const char * const kSecretSystemKey64 = xstr(SECRET_SYSTEM_KEY);
#endif

inline CadmiumCrypto::Vuc str64toVuc(const string& dataStr64)
{
    const CadmiumCrypto::Vuc dataVec64(dataStr64.begin(), dataStr64.end());
    return CadmiumCrypto::Vuc(Base64::decode(dataVec64));
}

inline string vucToStr64(const CadmiumCrypto::Vuc& dataVec)
{
    const CadmiumCrypto::Vuc dataVec64 = cadmium::base::Base64::encode(dataVec);
    return string(dataVec64.begin(), dataVec64.end());
}

inline string vucToStr64url(const CadmiumCrypto::Vuc& dataVec)
{
    const CadmiumCrypto::Vuc dataVec64 = cadmium::base::Base64::encodeUrlSafe(dataVec);
    return string(dataVec64.begin(), dataVec64.end());
}

RsaContext::ShaAlgo xShaAlgo(CadmiumCrypto::Algorithm shaAlgo)
{
    switch (shaAlgo)
    {
        case CadmiumCrypto::SHA1:   return RsaContext::SHA1;   break;
        case CadmiumCrypto::SHA224: return RsaContext::SHA224; break;
        case CadmiumCrypto::SHA256: return RsaContext::SHA256; break;
        case CadmiumCrypto::SHA384: return RsaContext::SHA384; break;
        case CadmiumCrypto::SHA512: return RsaContext::SHA512; break;
        default:                    assert(false);             break;
    }
    return RsaContext::SHA256;  // to keep compiler happy
}

const uint32_t kStartKeyHandle = 1;
const uint32_t kInvalidKeyHandle = 0;

vector<string>& split(const string& s, char delim, vector<string>& elems)
{
    stringstream ss(s);
    string item;
    while(std::getline(ss, item, delim))
    {
        elems.push_back(item);
    }
    return elems;
}

vector<string> split(const string &s, char delim)
{
    vector<string> elems;
    split(s, delim, elems);
    return elems;
}

inline string toB64String(const CadmiumCrypto::Vuc& vuc)
{
    CadmiumCrypto::Vuc vuc64 = Base64::encode(vuc);
    return string(vuc64.begin(), vuc64.end());
}

bool reconcileAlgVsUsage(CadmiumCrypto::Algorithm algorithm,
        const vector<CadmiumCrypto::KeyUsage>& keyUsage)
{
    // empty usage means default usage, so always ok
    if (keyUsage.empty())
        return true;

    set<CadmiumCrypto::KeyUsage> allowedKeyUsage;
    switch (algorithm)
    {
        case CadmiumCrypto::HMAC:
        case CadmiumCrypto::RSASSA_PKCS1_V1_5:
            allowedKeyUsage.insert(CadmiumCrypto::SIGN);
            allowedKeyUsage.insert(CadmiumCrypto::VERIFY);
            break;
        case CadmiumCrypto::RSAES_PKCS1_V1_5:
        case CadmiumCrypto::AES_CBC:
        case CadmiumCrypto::AES_GCM:
        case CadmiumCrypto::AES_CTR:
            allowedKeyUsage.insert(CadmiumCrypto::ENCRYPT);
            allowedKeyUsage.insert(CadmiumCrypto::DECRYPT);
            break;
        case CadmiumCrypto::RSA_OAEP:
            allowedKeyUsage.insert(CadmiumCrypto::ENCRYPT);
            allowedKeyUsage.insert(CadmiumCrypto::DECRYPT);
            allowedKeyUsage.insert(CadmiumCrypto::WRAP);
            allowedKeyUsage.insert(CadmiumCrypto::UNWRAP);
            break;
        case CadmiumCrypto::AES_KW:
            allowedKeyUsage.insert(CadmiumCrypto::WRAP);
            allowedKeyUsage.insert(CadmiumCrypto::UNWRAP);
            break;
        default:
            return false;
    }
    for (vector<CadmiumCrypto::KeyUsage>::const_iterator it = keyUsage.begin();
            it != keyUsage.end(); ++it)
    {
        if (!allowedKeyUsage.count(*it))
            return false;
    }

    return true;
}

// Returns true if the left side of the string is an exact match.
// For example, for "foobar", "foo" would return true but "oob" would not.
bool doesLeftSideOfStringMatch(const string& str, const string& matchStr)
{
    assert(!str.empty());
    assert(!matchStr.empty());
    size_t matchIndex = str.find(matchStr);
    if (matchIndex == string::npos)
        return false;
    return (matchIndex == 0);
}

// Returns true if the right side of the string is exactly match.
// For example, for "foobar", "bar" would return true but "oba" would not.

bool doesRightSideOfStringMatch(const string& str, const string& matchStr)
{
    assert(!str.empty());
    assert(!matchStr.empty());

    size_t matchIndex = str.rfind(matchStr);
    if (string::npos == matchIndex)
        return false;
    string foundMatch = str.substr(matchIndex);
    assert(!foundMatch.empty());

    bool isRigthSide = foundMatch == matchStr;
    // matchIndex is also the length of the left side of the string.
    assert(isRigthSide == (str.length() == matchIndex + matchStr.length()));
    return isRigthSide;
}

bool isHashSpecPresent(const base::Variant& algVar)
{
    CadmiumCrypto::Algorithm hashType;
    const Variant hashAlgVar = algVar["params"]["hash"];
    if (hashAlgVar.isString())
        hashType = toAlgorithm(algVar["params"]["hash"].string());
    else
        hashType = toAlgorithm(algVar["params"]["hash"]["name"].string());
    if (hashType == CadmiumCrypto::INVALID_ALGORITHM)
    {
        DLOG() << "ERROR: algorithm missing inner hash spec\n";
        return false;
    }
    if (!isAlgorithmSha(hashType))
    {
        DLOG() << "ERROR: algorithm inner hash is not SHA\n";
        return false;
    }
    return true;
}

int extractIntFromString(const string& str)
{
    int number = 0;
    string temp;
    for (size_t i=0; i < str.size(); i++)
    {
        //iterate the string to find the first "number" character
        //if found create another loop to extract it
        //and then break the current one
        //thus extracting the FIRST encountered numeric block
        if (isdigit(str[i]))
        {
            for (size_t a=i; a<str.size(); a++)
                temp += str[a];
          //the first numeric block is extracted
          break;
        }
    }
    istringstream stream(temp);
    stream >> number;
    return number;
}

bool isJweJs(const string& input)
{
    return input[0] == '{';
}

}   // namespace anonymous

CadmiumCrypto::CadmiumCryptoImpl::CadmiumCryptoImpl(IDeviceInfo * pDeviceInfo)
:   pDeviceInfo_(pDeviceInfo)
,   isInited_(false)
,   nextKeyHandle_(kStartKeyHandle)
,   systemKeyHandle_(kInvalidKeyHandle)
{
}

CadmiumCrypto::CadmiumCryptoImpl::~CadmiumCryptoImpl()
{
}

CadErr CadmiumCrypto::CadmiumCryptoImpl::init(const Vuc& prngSeed)
{
    if (isInited_)
        return CAD_ERR_ALREADY_INITIALIZED;

    // init OpenSSL
    if (prngSeed.size() < MIN_SEED_LEN)
        return CAD_ERR_BADARG;
    if (!OpenSSLLib::init(prngSeed))
        return CAD_ERR_INTERNAL;

    // create the system key used for export/import wrapping
    createSystemKey();

    // import pre-provisioned keys
    importPreSharedKeys();

    isInited_ = true;
    return CAD_ERR_OK;
}

void CadmiumCrypto::CadmiumCryptoImpl::importPreSharedKeys()
{
    const string currentOrigin(pDeviceInfo_->getOrigin());
    if (!currentOrigin.size())
    {
        DLOG() << "CadmiumCrypto::importPreSharedKeys: invalid page origin, skipping key import\n";
        return;
    }
    SampleKeyProvision skp;
    const SampleKeyProvision::NamedKeyVec& keyVec(skp.getNamedKeyVec());
    DLOG() << "Importing pre-shared keys:\n";
    for (SampleKeyProvision::NamedKeyVec::const_iterator nk = keyVec.begin(); nk != keyVec.end(); ++nk)
    {
        DLOG() << nk->name << ", " << Base64::decode(nk->id) << ", searching origins for " << currentOrigin << ": ";
        bool originOk = false;
        for (vector<string>::const_iterator org = nk->origins.begin(); org != nk->origins.end(); ++org)
        {
            if (!org->size())   // skip blank origin
                continue;
            DLOG() << *org << " ";
            if (doesRightSideOfStringMatch(currentOrigin, *org))
            {
                originOk = true;
                DLOG() << "(found) ";
            }
        }
        DLOG() << endl;
        if (!originOk)
        {
            DLOG() << "CadmiumCrypto::importPreSharedKeys: preshared key has no "
                    "origin compatible with " << currentOrigin << ", skipping\n";
            continue;
        }
        importNamedKey(*nk);
    }
}

uint32_t CadmiumCrypto::CadmiumCryptoImpl::importNamedKey(const NamedKey& nk)
{
    uint32_t keyHandle;
    CadErr err = importKeyInternal(RAW, vucToStr64(nk.key), nk.algVar, nk.extractable,
            nk.keyUsage, keyHandle);
    if (err != CAD_ERR_OK)
    {
        DLOG() << "CadmiumCrypto::importPreSharedKeys: WARNING: preshared key " <<
                nk.name << " failed\n";
        return kInvalidKeyHandle;
    }
    namedKeyMap_.insert(make_pair(nk.name, NamedKeySpec(keyHandle, nk.id)));
    return keyHandle;
}

// Create the AES-KW system key used for export/import wrapping.
// This key will be the same every time assuming the deviceID, script origin,
// and kSecretSystemKey64 are invariant.
void CadmiumCrypto::CadmiumCryptoImpl::createSystemKey()
{
    // make originVuc, a 256 bit hash of the origin string
    const string originStr(pDeviceInfo_->getOrigin());
    //DLOG() << "\toriginStr= " << originStr << endl;
    Vuc originShaVuc;
    if (!originStr.empty())
    {
        Vuc originVuc(originStr.begin(), originStr.end());
        Digester digester(DigestAlgo::SHA256());
        digester.init();
        digester.update(originVuc);
        originShaVuc = digester.final();
        assert(originShaVuc.size() == 32);
    }
    //DLOG() << "\toriginShaVuc(" <<  originShaVuc.size() << ")\t= " << NtbaUtil::toHexString(originShaVuc, "") << endl;

    // get 256 bit deviceId
    Vuc deviceIdVuc = pDeviceInfo_->getBinaryDeviceId();
    //DLOG() << "\tdeviceId(" <<  deviceIdVuc.size() << ")\t\t= " << NtbaUtil::toHexString(deviceIdVuc, "") << endl;
    assert(deviceIdVuc.size() == 32);

    // mix originVuc and deviceIdVuc together
    // this makes a device- and script-origin-bound data chunk
    if (!originShaVuc.empty())
    {
        for(int i=0; i < 32; ++i)
            deviceIdVuc[i] ^= originShaVuc[i];
    }
    //DLOG() << "\tdeviceId after(" <<  deviceIdVuc.size() << ")\t= " << NtbaUtil::toHexString(deviceIdVuc, "") << endl;

    // get secret system key
    const Vuc secretSystemKey(str64toVuc(kSecretSystemKey64));
    assert(secretSystemKey.size() == 32);
    //DLOG() << "\tsecretSystemKey\t\t= " << NtbaUtil::toHexString(secretSystemKey, "") << endl;

    // HMAC deviceIdVuc with the secret system key to get the new individualized
    // system key.
    // The resulting system key is device-bound, script-origin-bound, and bound
    // to this runtime binary.
    crypto::HMAC hmac(secretSystemKey);
    hmac.init();
    hmac.update(deviceIdVuc);
    Vuc keyVuc = hmac.final();
    //DLOG() << "\tkeyVuc\t\t\t\t= " << NtbaUtil::toHexString(keyVuc, "") << endl;

    // finally, mix in bytes from a hard-coded random table into keyVuc, driven
    // by deviceIdVuc
    for (int i=0; i < 32; ++i)
    {
        uint8_t idx = deviceIdVuc[i];
        uint8_t r = gRandTable[idx];
        keyVuc[i] ^= r;
    }
    //DLOG() << "\tkeyVuc\t\t\t\t= " << NtbaUtil::toHexString(keyVuc, "") << endl;

    DLOG() << "Created system key\n";

    // make a NamedKey and store
    VariantMap algVar;
    algVar["name"] = toString(CadmiumCrypto::AES_KW);
    vector<CadmiumCrypto::KeyUsage> keyUsage;
    keyUsage.push_back(WRAP); keyUsage.push_back(UNWRAP);
    const NamedKey nk("Kds", "", vector<string>(), keyVuc, SECRET, false, algVar, keyUsage);
    systemKeyHandle_ = importNamedKey(nk);  // required for generateKey(SYSTEM) hack
    assert(systemKeyHandle_ != kInvalidKeyHandle);
    //DLOG() << "\tsystemKeyHandle_ = " << systemKeyHandle_ << endl;
}

void CadmiumCrypto::CadmiumCryptoImpl::addEntropy(const string& entropyBytesStr64)
{
    if (!isInited_)
        return;
    const Vuc entropyBytesVuc = str64toVuc(entropyBytesStr64);
    if (entropyBytesVuc.empty())
        return;
    DLOG() << "CadmiumCrypto::addEntropy: adding " << entropyBytesVuc.size() <<
            " bytes of entropy to OpenSSL\n";
    // assume this is pure entropy (2nd arg, # bytes entropy == # bytes of the data)
    OpenSSLLib::add_entropy(entropyBytesVuc, entropyBytesVuc.size());
}

bool CadmiumCrypto::CadmiumCryptoImpl::hasKey(uint32_t keyHandle) const
{
    return keyMap_.count(keyHandle);
}

bool CadmiumCrypto::CadmiumCryptoImpl::isUsageAllowed(uint32_t keyHandle, KeyUsage keyUsage)
{
    assert(hasKey(keyHandle));
    const Key key = keyMap_[keyHandle];
    if (key.keyUsage.empty())   // empty keyUsage means all allowed
        return true;
    return std::find(key.keyUsage.begin(), key.keyUsage.end(), keyUsage) != key.keyUsage.end();
}

bool CadmiumCrypto::CadmiumCryptoImpl::isKeyAlgMatch(uint32_t keyHandle, Algorithm algorithm)
{
    assert(hasKey(keyHandle));
    const Algorithm keyAlgorithm = toAlgorithm(keyMap_[keyHandle].algVar["name"].string());
    return keyAlgorithm == algorithm;
}

CadErr CadmiumCrypto::CadmiumCryptoImpl::digest(Algorithm algorithm,
        const string& dataStr64, string& digestStr64)
{
    if (!isInited_)
        return CAD_ERR_NOT_INITIALIZED;

    // decode input data
    const Vuc dataVec = str64toVuc(dataStr64);
    if (dataVec.empty())
        return CAD_ERR_BADENCODING;

    // pick the algorithm
    shared_ptr<const DigestAlgo> algo;
    switch (algorithm)
    {
        case SHA1:   algo = DigestAlgo::SHA1();   break;
        case SHA224: algo = DigestAlgo::SHA224(); break;
        case SHA256: algo = DigestAlgo::SHA256(); break;
        case SHA384: algo = DigestAlgo::SHA384(); break;
        case SHA512: algo = DigestAlgo::SHA512(); break;
        default:     return CAD_ERR_UNKNOWN_ALGO;
    }

    // compute the digest
    Digester digester(algo);
    digester.init();
    digester.update(dataVec);
    const Vuc digestVec = digester.final();

    // encode the result
    digestStr64 = vucToStr64(digestVec);

    return CAD_ERR_OK;
}

CadErr CadmiumCrypto::CadmiumCryptoImpl::importKey(KeyFormat keyFormat,
    const string& keyData, const Variant& algVar, bool extractable,
    const vector<KeyUsage>& keyUsage, uint32_t& keyHandle)
{
    if (!isInited_)
        return CAD_ERR_NOT_INITIALIZED;
    return importKeyInternal(keyFormat, keyData, algVar, extractable, keyUsage, keyHandle);
}

CadErr CadmiumCrypto::CadmiumCryptoImpl::importKeyInternal(KeyFormat keyFormat,
    const string& keyData, const Variant& algVar, bool extractable,
    const vector<KeyUsage>& keyUsage, uint32_t& keyHandle)
{
    keyHandle = kInvalidKeyHandle;

    // keydata is always base64-encoded
    Vuc keyVuc(str64toVuc(keyData));
    if (keyVuc.empty())
        return CAD_ERR_BADENCODING;

    // JWK format is a special case, since the internal contents of the JWK may
    // override the algorithm, extractable, etc. input parms. Shunt it off to
    // a separate handler now.
    if (keyFormat == JWK)
        return importJwk(keyVuc, algVar, extractable, keyUsage, keyHandle);

    const Algorithm algType = toAlgorithm(algVar["name"].string());

    if (!reconcileAlgVsUsage(algType, keyUsage))
    {
        DLOG() << "CadmiumCrypto::importKey: ERROR: inconsistent algorithm vs usage\n";
        return CAD_ERR_INTERNAL;    // FIXME better error
    }

    shared_ptr<RsaContext> pRsaContext(new RsaContext());
    KeyType keyType;
    switch (algType)
    {
        case HMAC:
        case AES_CBC:
        case AES_GCM:
        case AES_CTR:
        case AES_KW:
        {
            if (keyFormat != RAW)
            {
                DLOG() << "CadmiumCrypto::importKey: ERROR: raw or jwk required for algorithm "
                        << toString(algType) << endl;
                return CAD_ERR_UNSUPPORTED_KEY_ENCODING;
            }
            // We assume RAW key input is always a symmetric secret key
            keyType = SECRET;

            // Wes and Mark say HMAC import must always include a hash
            if (isAlgorithmHmac(algType))
            {
                // For HMAC specifically, you must provide a hash
                if (!isHashSpecPresent(algVar))
                    return CAD_ERR_UNKNOWN_ALGO;
            }
            break;
        }
        case RSASSA_PKCS1_V1_5:
        case RSA_OAEP:
        case RSAES_PKCS1_V1_5:
        {
            switch (keyFormat)
            {
                case SPKI:
                {
                    // initialize the RSA context with the public SPKI-formatted key
                    if (!pRsaContext->setPublicSpki(keyVuc))
                        return CAD_ERR_CIPHERERROR;
                    // SPKI is always public
                    keyType = PUBLIC;
                    // Since this is a public key, it should be forced to be
                    // extractable.
                    extractable = true;
                    keyVuc.clear(); // the pRsaContext holds the goods now
                    break;
                }
                case PKCS8:
                {
                    // initialize the RSA context with the private PKCS#8-formatted key
                    if (!pRsaContext->setPrivatePkcs8(keyVuc))
                        return CAD_ERR_CIPHERERROR;
                    // PKCS8 is always private
                    keyType = PRIVATE;
                    keyVuc.clear(); // the pRsaContext holds the goods now
                    break;
                }
                default:
                {
                    DLOG() << "CadmiumCrypto::importKey: ERROR: spki, pkcs8, or jwk required for algorithm "
                            << toString(algType) << endl;
                    return CAD_ERR_UNSUPPORTED_KEY_ENCODING;
                }
            }
            break;
        }
        default:
        {
            DLOG() << "CadmiumCrypto::importKey: ERROR: unrecognized algorithm "
                    << toString(algType) << endl;
            return CAD_ERR_BADARG;
        }
    }

    // Finally, make a new Key object containing the extracted key and add it to
    // the key store, indexed by (output) keyHandle.
    // Note that extractable and keyUsage are copied through without processing.
    keyHandle = nextKeyHandle_++;
    Key key(keyVuc, pRsaContext, keyType, extractable, algVar, keyUsage);
    keyMap_[keyHandle] = key;

#ifdef BUILD_DEBUG
    if (!keyVuc.empty())
        DLOG() << "CadmiumCrypto::importKey: keyVuc  =\n" <<
            truncateLong(NtbaUtil::toHexString(keyVuc, "")) << endl;
#endif

    return CAD_ERR_OK;
}

CadErr CadmiumCrypto::CadmiumCryptoImpl::importJwk(const Vuc& keyVuc,
    const Variant& algVar, bool extractable, const vector<KeyUsage>& keyUsage,
    uint32_t& keyHandle)
{
    // NOTE: the input parms algVar, extractable, and keyUsage are used only if
    // corresponding fields in the JWK not present. They are fallbacks only.

    // Parse the JWK JSON
    // {
    //      'kty':     'RSA' or 'oct'         REQUIRED
    //      'alg:      'RSA1_5', 'A128'       OPTIONAL
    //      'use':     'sig', 'enc', 'wrap'   OPTIONAL
    //      'extractable':                    OPTIONAL
    //      <type-specific parms>             OPTIONAL
    // }
    const string keyStr(keyVuc.begin(), keyVuc.end());
    DLOG() << "CadmiumCrypto::importJwk: " << keyStr << endl;
    const Variant jwk(Variant::fromJSON(keyStr.c_str()));
    bool isFound;
    const string jwkKty = jwk.mapValue<string>("kty", &isFound);
    if (!isFound)
    {
        DLOG() << "CadmiumCrypto::importJwk: JWK missing required 'kty' field\n";
        return CAD_ERR_BADARG;  // FIXME better error
    }
    const string jwkAlg = jwk.mapValue<string>("alg");
    const string jwkUse = jwk.mapValue<string>("use");
    const string jwkExtractable = jwk.mapValue<string>("extractable");
    DLOG() << "\tjwkKty = " << jwkKty << endl;
    if (jwkAlg.size()) DLOG() << "\tjwkAlg = " << jwkAlg << endl;
    if (jwkUse.size()) DLOG() << "\tjwkUse = " << jwkUse << endl;
    if (!jwkExtractable.empty()) DLOG() << "\tjwkExtractable = " << jwkExtractable << endl;

    // resolve conflicts between JWK and input args

    // 'extractable' - should be the AND of the API and JWK values, if the latter exists
    bool myExtractable = jwkExtractable.empty() ?
            extractable : extractable && (jwkExtractable == "true");

    // 'alg'
    // Wes says JWK 'alg' contents, if present, should override input
    /*
    From an email from Mark. These are the JWK alg parameters to support
       | HS256        | HMAC using SHA-256 hash        | REQUIRED          |
       |              | algorithm                      |                   |
       | HS384        | HMAC using SHA-384 hash        | OPTIONAL          |
       |              | algorithm                      |                   |
       | HS512        | HMAC using SHA-512 hash        | OPTIONAL          |
       |              | algorithm                      |                   |
       | RS256        | RSASSA using SHA-256 hash      | RECOMMENDED       |
       |              | algorithm                      |                   |
       | RS384        | RSASSA using SHA-384 hash      | OPTIONAL          |
       |              | algorithm                      |                   |
       | RS512        | RSASSA using SHA-512 hash      | OPTIONAL          |
       |              | algorithm                      |                   |
       +----------------+---------------------------------+----------------+
       | RSA1_5         | RSAES-PKCS1-V1_5 [RFC3447]      | REQUIRED       |
       | RSA-OAEP       | RSAES using Optimal Asymmetric  | OPTIONAL       |
       |                | Encryption Padding (OAEP)       |                |
       |                | [RFC3447], with the default     |                |
       |                | parameters specified by RFC     |                |
       |                | 3447 in Section A.2.1           |                |
       | A128KW         | Advanced Encryption Standard    | RECOMMENDED    |
       |                | (AES) Key Wrap Algorithm        |                |
       |                | [RFC3394] using 128 bit keys    |                |
       | A256KW         | AES Key Wrap Algorithm using    | RECOMMENDED    |
       |                | 256 bit keys                    |                |
       | A128GCM       | AES in Galois/Counter Mode (GCM) | RECOMMENDED    |
       |               | [AES] [NIST.800-38D] using 128   |                |
       |               | bit keys                         |                |
       | A256GCM       | AES GCM using 256 bit keys       | RECOMMENDED    |
       +---------------+----------------------------------+----------------+

     What is missing is A128CBC (and A128CTR, though we don't need that), because
     there is no JSON Web Algorithm that uses A128CBC alone.

     I don't think there can be much doubt what the string should be (AxxxCBC) for
     xxx=128, 256, 384 etc. so we're on safe ground.
    */

    Variant myAlgVar;
    if (jwkAlg.size())
    {
        if (doesLeftSideOfStringMatch(jwkAlg, "HS"))
        {
            VariantMap hash;
            if (jwkAlg == "HS256")
                hash["name"] = "SHA-256";
            else if (jwkAlg == "HS384")
                hash["name"] = "SHA-384";
            else if (jwkAlg == "HS512")
                hash["name"] = "SHA-512";
            else
            {
                DLOG() << "CadmiumCrypto::importJwk: invalid HMAC hash\n";
                return CAD_ERR_UNKNOWN_ALGO;
            }
            myAlgVar["name"] = "HMAC";
            myAlgVar["params"]["hash"] = hash;
        }
        else if (doesLeftSideOfStringMatch(jwkAlg, "RSA"))  // do before "RS"
        {
            if (jwkAlg == "RSA1_5")
            {
                myAlgVar["name"] = "RSAES-PKCS1-v1_5";
            }
            else if (jwkAlg == "RSA-OAEP")
            {
                myAlgVar["name"] = "RSA-OAEP";
                VariantMap hash;
                hash["name"] = "SHA-1";
                myAlgVar["params"]["hash"] = hash;
            }
        }
        else if (doesLeftSideOfStringMatch(jwkAlg, "RS"))  // do after "RSA"
        {
            VariantMap hash;
            if (jwkAlg == "RS256")
            {
                hash["name"] = "SHA-256";
            }
            else if (jwkAlg == "RS384")
            {
                hash["name"] = "SHA-384";
            }
            else if (jwkAlg == "RS512")
            {
                hash["name"] = "SHA-512";
            }
            else
            {
                DLOG() << "CadmiumCrypto::importJwk: invalid RSASSA-PKCS1-v1_5 hash\n";
                return CAD_ERR_UNKNOWN_ALGO;
            }
            myAlgVar["name"] = "RSASSA-PKCS1-v1_5";
            myAlgVar["params"]["hash"] = hash;
        }
        else if (doesRightSideOfStringMatch(jwkAlg, "KW"))
        {
            if ( (jwkAlg != "A128KW") && (jwkAlg != "A256KW") )
            {
                DLOG() << "CadmiumCrypto::importJwk: unrecognized JWK KW alg " << jwkAlg << endl;
                return CAD_ERR_UNKNOWN_ALGO;
            }
            myAlgVar["name"] = "AES-KW";
        }
        else if (doesRightSideOfStringMatch(jwkAlg, "GCM"))
        {
            myAlgVar["name"] = "AES-GCM";
            // assume the inner hash output (tag) length must equal the key size
            int taglength = 0;
            if (jwkAlg == "A128GCM")
                taglength = 128;
            else if (jwkAlg == "A256GCM")
                taglength = 256;
            else
            {
                DLOG() << "CadmiumCrypto::importJwk: unsupported AES-GCM algorithm\n";
                return CAD_ERR_UNKNOWN_ALGO;
            }
            myAlgVar["params"]["tagLength"] = taglength;
            const string jwkIvStr = jwk.mapValue<string>("iv");
            if (jwkIvStr.size())
                myAlgVar["params"]["iv"] = jwkIvStr;
            const string jwkAad = jwk.mapValue<string>("data");
            if (jwkAad.size())
                myAlgVar["params"]["additionalData"] = jwk.mapValue<string>("data");
        }
        else if (doesRightSideOfStringMatch(jwkAlg, "CBC"))
        {
            myAlgVar["name"] = "AES-CBC";
            const string jwkIvStr = jwk.mapValue<string>("iv");
            if (jwkIvStr.size())
                myAlgVar["params"]["iv"] = jwkIvStr;
        }
        else
        {
            DLOG() << "CadmiumCrypto::importJwk: JWK unrecognized algorithm\n";
            return CAD_ERR_UNKNOWN_ALGO;
        }
    }
    else    // no 'alg' in the JWK, use input instead
    {
        if (algVar.isNull())
        {
            DLOG() << "CadmiumCrypto::importJwk: JDK contains no 'alg' and no algorithm provided as fallback\n";
            return CAD_ERR_UNKNOWN_ALGO;
        }
        myAlgVar = algVar;
    }

    // FIXME: Wes and Mark disagree on behavior here.
    // keyUsage:
    //    Mark - should be intersection of API and JWE values, if the latter exists
    //    Wes  - If present, the JWE value should override the API value completely
    // Below I have implemented Wes's behavior since it was the most recently
    // provided and backed by his implementation.
    vector<KeyUsage> myKeyUsage;
    if (jwkUse.size())
    {
        if (jwkUse == "sig")
        {
            myKeyUsage.push_back(SIGN);
            myKeyUsage.push_back(VERIFY);
        }
        else if (jwkUse == "enc")
        {
            myKeyUsage.push_back(ENCRYPT);
            myKeyUsage.push_back(DECRYPT);
        }
        else if (jwkUse == "wrap")
        {
            myKeyUsage.push_back(WRAP);
            myKeyUsage.push_back(UNWRAP);
        }
        else
        {
            myKeyUsage = keyUsage;
        }
    }
    else
    {
        myKeyUsage = keyUsage;
    }

    // verify key usage
    if (!reconcileAlgVsUsage(toAlgorithm(myAlgVar["name"].string()), myKeyUsage))
    {
        DLOG() << "CadmiumCrypto::importJwk: ERROR: inconsistent algorithm vs usage\n";
        return CAD_ERR_INTERNAL;    // FIXME better error
    }

    // extract / make the key material
    shared_ptr<RsaContext> pRsaContext;
    Vuc jwkKVuc;
    KeyType keyType;
    if (jwkKty == "oct")    // raw octet string in 'k' field
    {
        const string jwkKStr64 = jwk.mapValue<string>("k", &isFound);
        if (!isFound)
        {
            DLOG() << "CadmiumCrypto::importJwk: missing k field\n";
            return CAD_ERR_BADARG;  // FIXME better error
        }
        DLOG() << "\tjwkK = " << jwkKStr64 << endl;
        const Vuc jwkKVuc64(jwkKStr64.begin(), jwkKStr64.end());
        jwkKVuc = Base64::decodeUrlSafe(jwkKVuc64);

        const uint32_t actualKeySizeBits = jwkKVuc.size() * 8;
        DLOG() << "\tkeyLenghBits: " << actualKeySizeBits << endl;

        // JWK encodes the key length in bits in the algorithm name, like
        // 'A128CBC'. Validate the length of the key in 'k' against this.
        const uint32_t algKeySizeBits = extractIntFromString(jwkAlg);
        if (algKeySizeBits != actualKeySizeBits)
        {
            DLOG() << "CadmiumCrypto::importJwk: ERROR - raw key length from 'oct' "
                    "field inconsistent with JWK algorithm name in 'alg' field\n";
            return CAD_ERR_BADENCODING;     // FIXME better error
        }

        // We assume RAW key input is always a symmetric secret key
        keyType = SECRET;

    }
    else if (jwkKty == "RSA")   // 'n', 'e', and possibly 'd' fields provided
    {
        // keyData is base64-encoded JSON. It must always include the 'n'
        // (public modulus) and 'e' (public exponent) fields. If only these
        // fields are provided, we assume we want to create a public key. If in
        // addition the 'd' (private modulus) field is provided, we assume are
        // creating a private key.
        // FIXME: Officially there are a ton more fields for a JWK containing an
        // RSA private key!
        const string pubModStr64(jwk.mapValue<string>("n"));
        const string pubExpStr64(jwk.mapValue<string>("e"));
        if (pubModStr64.empty() || pubExpStr64.empty())
        {
            DLOG() << "CadmiumCrypto::importKey: JKW RSA missing required fields\n";
            return CAD_ERR_BADENCODING;     // FIXME bad error
        }
        const string privModStr64(jwk.mapValue<string>("d"));

        DLOG() << "CadmiumCrypto::importKey: n = " << truncateLong(pubModStr64) << endl;
        DLOG() << "CadmiumCrypto::importKey: e = " << pubExpStr64 << endl;
        if (!privModStr64.empty())
            DLOG() << "CadmiumCrypto::importKey: d = " << truncateLong(privModStr64) << endl;

        // decode the incoming data
        const Vuc pubModVuc = str64toVuc(pubModStr64);
        if (pubModVuc.empty())
            return CAD_ERR_BADENCODING;
        const Vuc pubExpVuc = str64toVuc(pubExpStr64);
        if (pubExpVuc.empty())
            return CAD_ERR_BADENCODING;
        Vuc privModVuc;
        if (!privModStr64.empty())
        {
            privModVuc = str64toVuc(privModStr64);
            if (privModVuc.empty())
                return CAD_ERR_BADENCODING;
        }

        // initialize the RSA context with this raw key
        pRsaContext.reset(new RsaContext());
        if (!pRsaContext->setRaw(pubModVuc, pubExpVuc, privModVuc))
            return CAD_ERR_CIPHERERROR;

        // We assume here we are making a public key if we were NOT provided a
        // private modulus, and conversely if we WERE given a private modulus
        // then we are are making a private key.
        // Also, any public key must be forced to extractable regardless of the
        // jwk or input parameter values.
        if (privModVuc.empty())
        {
            keyType = PUBLIC;
            myExtractable = true;
        }
        else
        {
            keyType = PRIVATE;
        }

        DLOG() << "CadmiumCrypto::importKey: JWK\n";
        DLOG() << "CadmiumCrypto::importKey: " << ((keyType == PUBLIC) ? "PUBLIC" : "PRIVATE") << endl;
    }
    else
    {
        DLOG() << "CadmiumCrypto::importJwk: invalid JWK kty field value " << jwkKty << endl;
        return CAD_ERR_BADARG;
    }

    // Finally, make the actual Key object
    keyHandle = nextKeyHandle_++;
    Key key(jwkKVuc, pRsaContext, keyType, myExtractable, myAlgVar, myKeyUsage);
    keyMap_[keyHandle] = key;

    return CAD_ERR_OK;
}

CadErr CadmiumCrypto::CadmiumCryptoImpl::exportKey(uint32_t keyHandle,
        KeyFormat format, string& keyStr64)
{
    if (!isInited_)
        return CAD_ERR_NOT_INITIALIZED;

    if (!hasKey(keyHandle))
        return CAD_ERR_BADKEYINDEX;

    // the key must be extractable
    Key key = keyMap_[keyHandle];
    if (!key.extractable)
    {
        DLOG() << "CadmiumCrypto::exportKey: key not extractable\n";
        return CAD_ERR_BADKEYNAME;  // FIXME, need better error
    }

    // shunt to special handling for JWK export
    if (format == JWK)
        return exportJwk(key, keyStr64);

    // Besides JWK, the other allowed export formats are:
    // RSA*:            spki (only) for public key, pkcs8 (only) for private key
    // AES* and HMAC:   raw
    Vuc keyVuc;
    const Algorithm algType = toAlgorithm(key.algVar["name"].string());
    if (isAlgorithmRsa(algType))
    {
        bool success;
        if (format == SPKI)
        {
            success = key.pRsaContext->getPublicSpki(keyVuc);
        }
        else if (format == PKCS8)
        {
            success = key.pRsaContext->getPrivatePkcs8(keyVuc);
        }
        else
        {
            DLOG() << "CadmiumCrypto::exportKey: Invalid format for RSA key export\n";
            return CAD_ERR_CIPHERERROR;  // FIXME, need better error
        }
        if (!success)
        {
            DLOG() << "CadmiumCrypto::exportKey: could not extract key\n";
            return CAD_ERR_CIPHERERROR;  // FIXME, need better error
        }
    }
    else if (isAlgorithmAes(algType) || isAlgorithmHmac(algType) || isAlgorithmDh(algType))
    {
        if (format != RAW)
        {
            DLOG() << "CadmiumCrypto::exportKey: AES and HMAC algorithms require RAW or JWK export\n";
            return CAD_ERR_BADKEYNAME;  // FIXME, need better error
        }
        keyVuc = key.key;
    }
    else
    {
        DLOG() << "CadmiumCrypto::exportKey: unknown algorithm\n";
        return CAD_ERR_UNKNOWN_ALGO;
    }

    // base64 encode the key data and return
    keyStr64 = vucToStr64(keyVuc);

    return CAD_ERR_OK;
}

CadErr CadmiumCrypto::CadmiumCryptoImpl::exportJwk(const Key& key, string& jwkStr64)
{
    // JWK has the following JSON structure
    // {
    //      'kty':          key type, e.g. 'RSA', 'EC', 'oct' (REQUIRED)
    //      'use':          key usage, e.g. 'sig', 'enc', 'wrap' (OPTIONAL)
    //      'alg:           key algorithm, e.g. 'RSA1_5, 'A128CBC', 'A128GCM', 'HS256', 'A128KW' (OPTIONAL)
    //      'kid':          key ID, e.g. ignore this (OPTIONAL)
    //      'extractable':  true or false (OPTIONAL)
    //      <kty-dependent parms>
    // }

    VariantMap jwkMap;
    // Note: we only support JWK export of symmetric and RSA public keys

    const Variant& algVar = key.algVar;
    const Algorithm algType = toAlgorithm(algVar["name"].string());

    // ---- 'kty' and kty-dependent parms
    if ( isAlgorithmAes(algType) || isAlgorithmHmac(algType) )
    {
        jwkMap["kty"] = "oct";
        // For a symmetric key, the only extra field is 'k', containing the
        // base64url encoding of the raw key.
        const Vuc keyDataVuc64(Base64::encodeUrlSafe(key.key));
        jwkMap["k"] = string(keyDataVuc64.begin(), keyDataVuc64.end());
    }
    else if (isAlgorithmRsa(algType))
    {
        jwkMap["kty"] = "RSA";
        if (key.type != PUBLIC)
        {
            DLOG() << "CadmiumCrypto::exportJwk: RSA private key export not implemented\n";
            return CAD_ERR_INTERNAL;    // FIXME better error
        }
        if (!key.pRsaContext->hasPublicKey())
        {
            DLOG() << "CadmiumCrypto::exportJwk: No RSA public key available\n";
            return CAD_ERR_INTERNAL;    // FIXME better error
        }
        // For an RSA public key, we need the public modulus 'n' and public
        // exponent 'e' fields.
        Vuc publicModulus;
        Vuc publicExponent;
        if (!key.pRsaContext->getPublicRaw(publicModulus, publicExponent))
        {
            DLOG() << "CadmiumCrypto::exportJwk: Error retrieving RSA public key\n";
            return CAD_ERR_INTERNAL;    // FIXME better error
        }
        const Vuc pubModVuc64(Base64::encodeUrlSafe(publicModulus));
        const Vuc pubExpVuc64(Base64::encodeUrlSafe(publicExponent));
        jwkMap["n"] = string(pubModVuc64.begin(), pubModVuc64.end());
        jwkMap["e"] = string(pubExpVuc64.begin(), pubExpVuc64.end());
    }
    else
    {
        DLOG() << "CadmiumCrypto::exportJwk: JWK export unsupported key algorithm\n";
        return CAD_ERR_INTERNAL;    // FIXME better error
    }

    // ---- 'use'
    // assume the the key.keyUsage vector is self-consistent and consistent with
    // key.algorithm, since this was checked when the key was created
    // Note there is an incomplete translation from WebCrypto use to JWK use.
    string useStr;
    for (vector<KeyUsage>::const_iterator it = key.keyUsage.begin(); it != key.keyUsage.end(); ++it)
    {
        string lastUseStr;
        switch (*it)
        {
            case ENCRYPT:
            case DECRYPT:
                useStr = "enc";
                break;
            case SIGN:
            case VERIFY:
                useStr = "sig";
                break;
            case WRAP:
            case UNWRAP:
                useStr = "wrap";
                break;
            case DERIVE:
            default:
                useStr.clear();
                break;  // no translation available
        }
        // The author of the JWK spec (Mike Jones) says here
        // http://www.ietf.org/mail-archive/web/jose/current/msg00828.html
        // that the JWK "use" value should be omitted if more than one kind of
        // use for the key is intended, where "kind" = {enc, sign, wrap}
        if (!lastUseStr.empty() && lastUseStr != useStr)
        {
            useStr.clear();
            break;
        }
        lastUseStr = useStr;
    }
    if (!useStr.empty())
        jwkMap["use"] = useStr;

    // ---- 'alg'
    const size_t keyLengthBits = key.key.size() * 8;
    switch (algType)
    {
        case HMAC:
        {
            switch (keyLengthBits)
            {
                case 256: jwkMap["alg"] = "HS256"; break;
                case 384: jwkMap["alg"] = "HS384"; break;
                case 512: jwkMap["alg"] = "HS512"; break;
                default:
                    DLOG() << "CadmiumCrypto::exportJwk: could not find JWK "
                        "HMAC alg for keylength = " << keyLengthBits << endl;
                    return CAD_ERR_INTERNAL;    // FIXME better error
                    break;
            }
            break;
        }
        case AES_CBC:
        {
            switch (keyLengthBits)
            {
                case 128: jwkMap["alg"] = "A128CBC"; break;
                case 256: jwkMap["alg"] = "A256CBC"; break;
                case 384: jwkMap["alg"] = "A384CBC"; break;
                case 512: jwkMap["alg"] = "A512CBC"; break;
                default:
                    DLOG() << "CadmiumCrypto::exportJwk: could not find JWK "
                        "AES-CBC alg for keylength = " << keyLengthBits << endl;
                    return CAD_ERR_INTERNAL;    // FIXME better error
                    break;
            }
            break;
        }
        case AES_GCM:
        {
            switch (keyLengthBits)
            {
                case 128: jwkMap["alg"] = "A128GCM"; break;
                case 256: jwkMap["alg"] = "A256GCM"; break;
                default:
                    DLOG() << "CadmiumCrypto::exportJwk: could not find JWK "
                        "AES-GCM alg for keylength = " << keyLengthBits << endl;
                    return CAD_ERR_INTERNAL;    // FIXME better error
                    break;
            }
            break;
        }
        case AES_CTR:
        {
            if (keyLengthBits != 128)
            {
                DLOG() << "CadmiumCrypto::exportJwk: could not find JWK "
                        "AES-CTR alg for keylength = " << keyLengthBits << endl;
                return CAD_ERR_INTERNAL;    // FIXME better error
            }
            jwkMap["alg"] = "A128CTR";
            break;
        }
        case RSAES_PKCS1_V1_5:
        {
            jwkMap["alg"] = "RSA1_5";
            break;
        }
        case RSASSA_PKCS1_V1_5:
        {
            const Algorithm shaAlgType= toAlgorithm(key.algVar["params"]["hash"]["name"].string());
            assert(isAlgorithmSha(shaAlgType));
            switch (shaAlgType)
            {
                case SHA256: jwkMap["alg"] = "RS256"; break;
                case SHA384: jwkMap["alg"] = "RS384"; break;
                case SHA512: jwkMap["alg"] = "RS512"; break;
                default:
                    DLOG() << "CadmiumCrypto::exportJwk: found RSASSA_PKCS1_V1_5 alg with"
                            "invalid inner SHA" << toString(shaAlgType) << endl;
                    return CAD_ERR_INTERNAL;    // FIXME better error
                    break;
           }
           break;
        }
        case RSA_OAEP:
        {
            jwkMap["alg"] = "RSA-OAEP";
            break;
        }
        case AES_KW:
        {
            switch (keyLengthBits)
            {
                case 128:
                    jwkMap["alg"] = "A128KW";
                    break;
                case 256:
                    jwkMap["alg"] = "A256KW";
                    break;
                default:
                    DLOG() << "CadmiumCrypto::exportJwk: AES keywrap incompatible key length "
                        << keyLengthBits << " bits, only 128 and 256 supported\n";
                    return CAD_ERR_INTERNAL;
                    break;
            }
            break;
        }
        default:
        {
            DLOG() << "CadmiumCrypto::exportJwk: Unable to translate exported key"
                    " algorithm " << toString(algType) << " to JWK alg value\n";
            return CAD_ERR_INTERNAL;
            break;
        }
    }

    // ---- 'extractable'
    jwkMap["extractable"] = key.extractable;

    // make the JSON representation
    const string jwkJson = Variant(jwkMap).toJSON();
    DLOG() << "CadmiumCrypto::exportJwk: JSON = " << jwkJson << endl;

    jwkStr64 = Base64::encode(jwkJson);

    return CAD_ERR_OK;

}

CadErr CadmiumCrypto::CadmiumCryptoImpl::getKeyInfo(uint32_t keyHandle,
        KeyType& type, bool& extractable, Variant& algVar,
        vector<KeyUsage>& usage) const
{
    if (!isInited_)
        return CAD_ERR_NOT_INITIALIZED;

    if (!hasKey(keyHandle))
        return CAD_ERR_BADKEYINDEX;

    // STL map operator[] is intolerant to const args...
    Key key = const_cast<CadmiumCrypto::CadmiumCryptoImpl *>(this)->keyMap_[keyHandle];
    type = key.type;
    extractable = key.extractable;
    algVar = key.algVar;
    usage = key.keyUsage;

    return CAD_ERR_OK;
}

CadErr CadmiumCrypto::CadmiumCryptoImpl::aesPre(uint32_t keyHandle,
        KeyUsage keyUsage, const string& ivInStr64, const string& dataInStr64,
        Algorithm algorithm, Vuc& ivVec, Vuc& dataVec, Vuc& keyVec)
{
    if (!isInited_)
        return CAD_ERR_NOT_INITIALIZED;

    if (!hasKey(keyHandle))
        return CAD_ERR_BADKEYINDEX;

    // verify the provided key is permitted this usage
    if (!isUsageAllowed(keyHandle, keyUsage))
    {
        DLOG() << "CadmiumCrypto::aes: operation disallowed by keyUsage\n";
        return CAD_ERR_KEY_USAGE;
    }

    // verify the provided key is intended for this algorithm
    if (!isKeyAlgMatch(keyHandle, algorithm))
    {
        DLOG() << "CadmiumCrypto::aes: operation incompatible with key algorithm\n";
        return CAD_ERR_KEY_USAGE;
    }

    // convert iv
    ivVec = str64toVuc(ivInStr64);
    if (ivVec.empty())
        return CAD_ERR_BADENCODING;
    if (ivVec.size() < AesCbcCipher::BLOCKSIZE) // same block size for all AES ciphers
    {
        DLOG() << "CadmiumCrypto::aes: IV too short, must be " <<
                AesCbcCipher::BLOCKSIZE << " bytes or longer\n";
        return CAD_ERR_BADIV;
    }

    // convert input data
    dataVec = str64toVuc(dataInStr64);

    // check the key
    keyVec = keyMap_[keyHandle].key;
    if (keyVec.size() != AesCbcCipher::KL128 &&  // same key sizes for all AES ciphers
        keyVec.size() != AesCbcCipher::KL192 &&
        keyVec.size() != AesCbcCipher::KL256)
    {
        DLOG() << "CadmiumCrypto::aesCbc: incompatible key length, must be 128, 192, or 256\n";
        return CAD_ERR_BADIV;
    }

    return CAD_ERR_OK;
}

CadErr CadmiumCrypto::CadmiumCryptoImpl::aesCbc(uint32_t keyHandle,
        const string& ivInStr64, const string& dataInStr64, CipherOp cipherOp,
        string& dataOutStr64)
{
    const KeyUsage keyUsage = (cipherOp == DOENCRYPT) ? ENCRYPT : DECRYPT;

    Vuc ivVec, dataVec, keyVec;
    CadErr err = aesPre(keyHandle, keyUsage, ivInStr64, dataInStr64,
        AES_CBC, ivVec, dataVec, keyVec);
    if (err != CAD_ERR_OK)
        return err;

    // do the operation
    AesCbcCipher cipher(keyVec, ivVec);
    Vuc resultVec;
    bool success;
    if (cipherOp == DOENCRYPT)
        success = cipher.encrypt(dataVec, resultVec);
    else
        success = cipher.decrypt(dataVec, resultVec);
    if (!success)
        return CAD_ERR_CIPHERERROR;

    // encode results and return
    dataOutStr64 = vucToStr64(resultVec);

    return CAD_ERR_OK;
}

CadErr CadmiumCrypto::CadmiumCryptoImpl::aesGcm(uint32_t keyHandle,
        const string& ivInStr64, const string& dataInStr64, const string& aadInStr64,
        uint8_t taglenBits, CipherOp cipherOp, string& dataOutStr64)
{
    Vuc ivVuc, dataVuc, keyVuc;
    CadErr err = aesPre(keyHandle, ENCRYPT, ivInStr64, dataInStr64,
        AES_GCM, ivVuc, dataVuc, keyVuc);
    if (err != CAD_ERR_OK)
        return err;

    // convert the aad
    const Vuc aadVuc = str64toVuc(aadInStr64);
    if (aadVuc.empty())
        return CAD_ERR_BADENCODING;

    AesGcmCipher cipher(keyVuc, ivVuc);
    Vuc tagVuc, outVuc;
    // round tagLenBits to a multiple of 8, to avoid padding issues
    taglenBits += (7 - ((taglenBits - 1) % 8));
    const uint8_t tagLenBytes = taglenBits / 8;
    if (cipherOp == DODECRYPT)
    {
        // extract the tag and trim the input data
        const uint32_t dataLenBytes = dataVuc.size() - tagLenBytes;
        const Vuc::iterator tagIt = dataVuc.begin() + dataLenBytes;
        Vuc(tagIt, dataVuc.end()).swap(tagVuc);
        assert(tagVuc.size() == tagLenBytes);
        Vuc(dataVuc.begin(), dataVuc.begin() + dataLenBytes).swap(dataVuc);
        assert(dataVuc.size() == dataLenBytes);

        // decrypt
        Vuc clearText;
        const bool success = cipher.decrypt(dataVuc, aadVuc, tagVuc, outVuc);
        if (!success)
            return CAD_ERR_CIPHERERROR;
    }
    else // cipherOp == DOENCRYPT
    {
        // encrypt
        const bool success = cipher.encrypt(dataVuc, aadVuc, outVuc, tagVuc);
        if (!success)
            return CAD_ERR_CIPHERERROR;

        // truncate the auth tag and concatenate it to the output ciphertext
        if (tagVuc.size() != tagLenBytes)
            Vuc(tagVuc.begin(), tagVuc.begin() + tagLenBytes).swap(tagVuc);
        assert(tagVuc.size() == tagLenBytes);
        outVuc.insert(outVuc.end(), tagVuc.begin(), tagVuc.end());
    }

    // encode results and return
    dataOutStr64 = vucToStr64(outVuc);

    return CAD_ERR_OK;
}

CadErr CadmiumCrypto::CadmiumCryptoImpl::hmac(uint32_t keyHandle, Algorithm shaAlgo,
        KeyUsage opUsage, const string& dataStr64, string& hmacStr64)
{
    if (!isInited_)
        return CAD_ERR_NOT_INITIALIZED;

    if (!hasKey(keyHandle))
        return CAD_ERR_BADKEYINDEX;

    if (!isUsageAllowed(keyHandle, opUsage))
    {
        DLOG() << "CadmiumCrypto::rsaCrypt: operation disallowed by keyUsage\n";
        return CAD_ERR_KEY_USAGE;
    }

    // verify the provided key is intended for this algorithm
    if (!isKeyAlgMatch(keyHandle, HMAC))
    {
        DLOG() << "CadmiumCrypto::hmac: operation incompatible with key algorithm\n";
        return CAD_ERR_KEY_USAGE;
    }

    // Wes and Mark say that we must validate the hash associated with the key
    // matches that of the hmac requested
    const Algorithm keyShaAlgo = toAlgorithm(keyMap_[keyHandle].algVar["params"]["hash"]["name"].string());
    if (shaAlgo != keyShaAlgo)
    {
        DLOG() << "CadmiumCrypto::hmac: request HMAC hash does not match key hash\n";
        return CAD_ERR_HMACERROR;
    }

    // decode input data
    const Vuc dataVec = str64toVuc(dataStr64);
    if (dataVec.empty())
        return CAD_ERR_BADENCODING;

    // select the inner hash function
    shared_ptr<const DigestAlgo> digestAlgo;
    switch (shaAlgo)
    {
        case SHA1:   digestAlgo = DigestAlgo::SHA1();   break;
        case SHA224: digestAlgo = DigestAlgo::SHA224(); break;
        case SHA256: digestAlgo = DigestAlgo::SHA256(); break;
        case SHA384: digestAlgo = DigestAlgo::SHA384(); break;
        case SHA512: digestAlgo = DigestAlgo::SHA512(); break;
        default:     assert(false);                     break;
    }

    // do the HMAC; this operation results in a base64-encoded Vuc
    crypto::HMAC hmac(keyMap_[keyHandle].key, digestAlgo);
    const Vuc& resultVec64(hmac.hmac(dataVec));

    // copy result to output string
    hmacStr64 = string(resultVec64.begin(), resultVec64.end());

    return CAD_ERR_OK;
}

CadErr CadmiumCrypto::CadmiumCryptoImpl::rsaKeyGen(const Variant& algVar,
        bool extractable, vector<KeyUsage> keyUsage, uint32_t& pubKeyHandle,
        uint32_t& privKeyHandle)
{
    if (!isInited_)
        return CAD_ERR_NOT_INITIALIZED;

    const Algorithm algType = toAlgorithm(algVar["name"].string());

    if (!isAlgorithmRsa(algType))
    {
        DLOG() << "CadmiumCrypto::rsaKeyGen: ERROR: not an RSA algorithm\n";
        return CAD_ERR_INTERNAL;    // FIXME better error
    }

    if (!reconcileAlgVsUsage(algType, keyUsage))
    {
        DLOG() << "CadmiumCrypto::rsaKeyGen: ERROR: inconsistent algorithm vs usage\n";
        return CAD_ERR_INTERNAL;    // FIXME better error
    }

    // get modulusLength from algorithm object
    if (!algVar.contains("params") && !algVar["params"].contains("modulusLength"))
    {
        DLOG() << "CadmiumCrypto::rsaKeyGen: ERROR: algorithm missing modulusLength param\n";
        return CAD_ERR_INTERNAL;    // FIXME better error
    }
    const int modLen = algVar["params"].mapValue<int>("modulusLength");
    DLOG() << "\tmodulusLength: " << modLen << endl;

    // get publicExponent from algorithm object
    if (!algVar["params"].contains("publicExponent"))
    {
        DLOG() << "CadmiumCrypto::rsaKeyGen: ERROR: algorithm missing publicExponent param\n";
        return CAD_ERR_INTERNAL;    // FIXME better error
    }
    const string pubExpStr64 = algVar["params"].mapValue<string>("publicExponent");
    DLOG() << "\tpublicExponent: " << pubExpStr64 << endl;

    // decode the public exponent
    const Vuc pubExpVec = str64toVuc(pubExpStr64);
    if (pubExpVec.empty())
        return CAD_ERR_BADENCODING;
    // We need an uint64_t for the public exponent arg to RsaContext.generate()
    size_t nBytes = sizeof(unsigned long);
    size_t pubExpVecSize = pubExpVec.size();
    size_t foo = std::min(nBytes, pubExpVecSize);
    uint64_t pubExp = 0;
    for (size_t i = 0; i < foo; ++i)
        pubExp |= (pubExpVec[i] << i*8);

    // make a new RSA context and generate keys
    shared_ptr<RsaContext> pRsaContext(new RsaContext());
    bool success = pRsaContext->generate(modLen, pubExp);
    if (!success)
        return CAD_ERR_KEYGEN;

    // Note: The input extractable value only applies to the private key. The
    // public key should always be forced to extractable = true.

    // make a Key object for the public key and record it in the keyMap
    const Vuc emptyVuc;
    pubKeyHandle = nextKeyHandle_++;    // pubKeyHandle is output parm
    const Key pubKey(emptyVuc, pRsaContext, PUBLIC, true, algVar, keyUsage);
    keyMap_[pubKeyHandle] = pubKey;

    // likewise for the private key
    privKeyHandle = nextKeyHandle_++;   // privKeyHandle is output parm
    const Key privKey(emptyVuc, pRsaContext, PRIVATE, extractable, algVar, keyUsage);
    keyMap_[privKeyHandle] = privKey;

    return CAD_ERR_OK;
}

CadErr CadmiumCrypto::CadmiumCryptoImpl::rsaCrypt(uint32_t keyHandle,
        const string& dataInStr64, CipherOp cipherOp, string& dataOutStr64)
{
    if (!isInited_)
        return CAD_ERR_NOT_INITIALIZED;

    if (!hasKey(keyHandle))
        return CAD_ERR_BADKEYINDEX;

    // verify the provided key is permitted this usage
    const KeyUsage keyUsage = (cipherOp == DOENCRYPT) ? ENCRYPT : DECRYPT;
    if (!isUsageAllowed(keyHandle, keyUsage))
    {
        DLOG() << "CadmiumCrypto::rsaCrypt: operation disallowed by keyUsage\n";
        return CAD_ERR_KEY_USAGE;
    }

    // verify the provided key is intended for this algorithm
    if (!isKeyAlgMatch(keyHandle, RSAES_PKCS1_V1_5) && !isKeyAlgMatch(keyHandle, RSA_OAEP))
    {
        DLOG() << "CadmiumCrypto::rsaCrypt: operation incompatible with key algorithm\n";
        return CAD_ERR_KEY_USAGE;
    }

    // convert input data
    Vuc dataVec = str64toVuc(dataInStr64);

    DLOG() << "CadmiumCrypto::rsaCrypt: inData = " << truncateLong(dataInStr64) << endl;

    const RsaContext::Padding padding =
            isKeyAlgMatch(keyHandle, RSA_OAEP) ? RsaContext::PKCS1_OAEP : RsaContext::PKCS1;

    // do the operation
    Vuc resultVec;
    if (cipherOp == DOENCRYPT)
    {
        bool success = keyMap_[keyHandle].pRsaContext->publicEncrypt(dataVec, resultVec, padding);
        if (!success)
            return CAD_ERR_CIPHERERROR;
    }
    else
    {
        bool success = keyMap_[keyHandle].pRsaContext->privateDecrypt(dataVec, resultVec, padding);
        if (!success)
            return CAD_ERR_CIPHERERROR;
    }

    // encode results and return
    dataOutStr64 = vucToStr64(resultVec);

    DLOG() << "CadmiumCrypto::rsaCrypt: outData = " << truncateLong(dataOutStr64) << endl;

    return CAD_ERR_OK;
}

CadErr CadmiumCrypto::CadmiumCryptoImpl::rsaSign(uint32_t keyHandle, Algorithm shaAlgo,
        const string& dataStr64, string& sigStr64)
{
    if (!isInited_)
        return CAD_ERR_NOT_INITIALIZED;

    if (!hasKey(keyHandle))
        return CAD_ERR_BADKEYINDEX;

    // verify the provided key is permitted this usage
    if (!isUsageAllowed(keyHandle, SIGN))
    {
        DLOG() << "CadmiumCrypto::rsaCrypt: operation disallowed by keyUsage\n";
        return CAD_ERR_KEY_USAGE;
    }

    // verify the provided key is intended for this algorithm
    if (!isKeyAlgMatch(keyHandle, RSASSA_PKCS1_V1_5))
    {
        DLOG() << "CadmiumCrypto::rsaSign: operation incompatible with key algorithm\n";
        return CAD_ERR_KEY_USAGE;
    }

    // decode input data
    const Vuc dataVec = str64toVuc(dataStr64);

    Vuc resultVec;
    bool success = keyMap_[keyHandle].pRsaContext->privateSign(dataVec, xShaAlgo(shaAlgo), resultVec);
    if (!success)
        return CAD_ERR_CIPHERERROR;

    // encode results and return
    sigStr64 = vucToStr64(resultVec);

    return CAD_ERR_OK;
}

CadErr CadmiumCrypto::CadmiumCryptoImpl::rsaVerify(uint32_t keyHandle,
        Algorithm shaAlgo, const string& dataStr64, const string& sigStr64,
        bool& isVerified)
{
    if (!isInited_)
        return CAD_ERR_NOT_INITIALIZED;

    if (!hasKey(keyHandle))
        return CAD_ERR_BADKEYINDEX;

    // verify the provided key is permitted this usage
    if (!isUsageAllowed(keyHandle, VERIFY))
    {
        DLOG() << "CadmiumCrypto::rsaCrypt: operation disallowed by keyUsage\n";
        return CAD_ERR_KEY_USAGE;
    }

    // verify the provided key is intended for this algorithm
    if (!isKeyAlgMatch(keyHandle, RSASSA_PKCS1_V1_5))
    {
        DLOG() << "CadmiumCrypto::rsaVerify: operation incompatible with key algorithm\n";
        return CAD_ERR_KEY_USAGE;
    }

    // decode input data
    const Vuc dataVec = str64toVuc(dataStr64);

    // decode input sig
    const Vuc sigVec = str64toVuc(sigStr64);
    if (sigVec.empty())
        return CAD_ERR_BADENCODING;

    isVerified = keyMap_[keyHandle].pRsaContext->publicVerify(dataVec, xShaAlgo(shaAlgo), sigVec);
    return CAD_ERR_OK;
}

CadErr CadmiumCrypto::CadmiumCryptoImpl::dhKeyGen(const Variant& algVar, bool extractable,
        vector<KeyUsage> keyUsage, uint32_t& pubKeyHandle, uint32_t& privKeyHandle)
{
    if (!isInited_)
        return CAD_ERR_NOT_INITIALIZED;

    const Algorithm algType = toAlgorithm(algVar["name"].string());

    assert(isAlgorithmDh(algType)); (void)algType;

    // get prime from algorithm object
    if (!algVar.contains("params") && !algVar["params"].contains("prime"))
    {
        DLOG() << "CadmiumCrypto::rsaKeyGen: ERROR: algorithm params missing prime\n";
        return CAD_ERR_INTERNAL;    // FIXME better error
    }
    const string primeStr64 = algVar["params"].mapValue<string>("prime");
    DLOG() << "\tprime: " << primeStr64 << endl;
    const Vuc primeVuc = str64toVuc(primeStr64);
    if (primeVuc.empty())
        return CAD_ERR_BADENCODING;

    // get generator from algorithm object
    if (!algVar.contains("params") && !algVar["params"].contains("generator"))
    {
        DLOG() << "CadmiumCrypto::rsaKeyGen: ERROR: algorithm params missing generator\n";
        return CAD_ERR_INTERNAL;    // FIXME better error
    }
    const string generatorStr64 = algVar["params"].mapValue<string>("generator");
    DLOG() << "\tpublicExponent: " << generatorStr64 << endl;
    const Vuc generatorVuc = str64toVuc(generatorStr64);
    if (generatorVuc.empty())
        return CAD_ERR_BADENCODING;

    // make a new DH context and generate keys
    shared_ptr<DiffieHellmanContext> pDhContext(new DiffieHellmanContext());
    bool success = pDhContext->init(primeVuc, generatorVuc);
    if (!success)
        return CAD_ERR_KEYGEN;

    // Note: The input extractable value only applies to the private key. The
    // public key should always be forced to extractable = true.

    // make a Key object for the public key and record it in the keyMap
    pubKeyHandle = nextKeyHandle_++;    // pubKeyHandle is output parm
    const Key pubKey(pDhContext->getPubKey(), pDhContext, PUBLIC, true, algVar, keyUsage);
    keyMap_[pubKeyHandle] = pubKey;

    // likewise for the private key
    privKeyHandle = nextKeyHandle_++;   // privKeyHandle is output parm
    const Key privKey(pDhContext->getPrivKey(), pDhContext, PRIVATE, extractable, algVar, keyUsage);
    keyMap_[privKeyHandle] = privKey;

    return CAD_ERR_OK;
}

CadErr CadmiumCrypto::CadmiumCryptoImpl::dhDerive(uint32_t baseKeyHandle,
        const string& peerPublicKeyStr64, const Variant& derivedAlgObj,
        bool derivedExtractable, vector<KeyUsage> derivedKeyUsage,
        uint32_t& derivedKeyHandle)
{
    if (!isInited_)
        return CAD_ERR_NOT_INITIALIZED;

    // check base key
    if (!hasKey(baseKeyHandle))
        return CAD_ERR_BADKEYINDEX;

    // verify the provided base key is permitted this usage
    if (!isUsageAllowed(baseKeyHandle, DERIVE))
    {
        DLOG() << "CadmiumCrypto::rsaCrypt: operation disallowed by keyUsage\n";
        return CAD_ERR_KEY_USAGE;
    }

    // verify the provided base key is intended for this algorithm
    if (!isKeyAlgMatch(baseKeyHandle, DH))
    {
        DLOG() << "CadmiumCrypto::dhDerive: operation incompatible with key algorithm\n";
        return CAD_ERR_KEY_USAGE;
    }

    // decode peer public key data
    const Vuc pubKeyVec = str64toVuc(peerPublicKeyStr64);
    if (pubKeyVec.empty())
        return CAD_ERR_BADENCODING;

    // compute the shared secret
    const shared_ptr<DiffieHellmanContext> pDhContext(keyMap_[baseKeyHandle].pDhContext);
    assert(pDhContext);
    bool success = pDhContext->computeSharedSecret(pubKeyVec);
    if (!success)
    {
        DLOG() << "CadmiumCrypto::dhDerive: shared secret computation failed\n";
        return CAD_ERR_KEYGEN;
    }

    // retrieve the shared secret and create a new Key object in the key store
    const Vuc sharedSecret(pDhContext->getSharedSecret());
    assert(!sharedSecret.empty());
    derivedKeyHandle = nextKeyHandle_++;    // derivedKeyHandle is output parm
    const Key derivedKey(sharedSecret, pDhContext, SECRET, derivedExtractable,
            derivedAlgObj, derivedKeyUsage);
    keyMap_[derivedKeyHandle] = derivedKey;

    return CAD_ERR_OK;
}

CadErr CadmiumCrypto::CadmiumCryptoImpl::unwrapJwe(const string& keyDataStr64,
        uint32_t wrappingKeyHandle, const Variant& algVar, bool extractable,
        const vector<KeyUsage>& keyUsage, uint32_t& keyHandle)
{
    if (!isInited_)
        return CAD_ERR_NOT_INITIALIZED;

    // http://www.w3.org/2012/webcrypto/wiki/KeyWrap_Proposal

    // NOTE: the input parms algVar, extractable, and keyUsage are not used by
    // this method. They are passed through to the final importJwk call to be
    // applied to the unwrapped key.

    string keyDataStr(Base64::decode(keyDataStr64));
    if (keyDataStr.empty())
    {
        DLOG() << "CadmiumCrypto::unwrapJwe: bad jwe data\n";
        return CAD_ERR_BADENCODING; // TODO better error
    }

    // try each recipient in a JWE-JS until one passes or they are exhausted
    if (isJweJs(keyDataStr))
    {
        const Variant jweJsVar = Variant::fromJSON(keyDataStr.c_str());
        const VariantArray recipients = jweJsVar["recipients"].array();
        for (size_t rcpIdx = 0; rcpIdx < recipients.size(); ++rcpIdx)
        {
            DLOG() << "CadmiumCrypto::unwrapJwe: trying JWE-JS recipient " <<
                    rcpIdx+1 << " of " << recipients.size() << endl;
            vector<string> jweStrVec;
            const Variant recipientVar = recipients[rcpIdx];
            jweStrVec.push_back(recipientVar["header"].string());
            jweStrVec.push_back(recipientVar["encrypted_key"].string());
            jweStrVec.push_back(jweJsVar["initialization_vector"].string());
            jweStrVec.push_back(jweJsVar["ciphertext"].string());
            jweStrVec.push_back(recipientVar["integrity_value"].string());
            if (unwrapJwe(jweStrVec, wrappingKeyHandle, algVar, extractable,
                    keyUsage, keyHandle) == CAD_ERR_OK)
            {
                DLOG() << "CadmiumCrypto::unwrapJwe: JWE-JS recipient " << rcpIdx+1
                        << " OK" << endl;
                return CAD_ERR_OK;
            }
            jweStrVec.clear();
        }
        DLOG() << "CadmiumCrypto::unwrapJwe: Failed to unwrap after trying all recipients\n";
        return CAD_ERR_BADENCODING; // TODO better error
    }
    else
    {
        const vector<string> jweStrVec = split(keyDataStr, '.');
        return unwrapJwe(jweStrVec, wrappingKeyHandle, algVar, extractable,
                keyUsage, keyHandle);
    }
}

CadErr CadmiumCrypto::CadmiumCryptoImpl::unwrapJwe(const vector<string>& jweStrVec,
        uint32_t wrappingKeyHandle, const Variant& algVar, bool extractable,
        const vector<KeyUsage>& keyUsage, uint32_t& keyHandle)
{
    const string& headerStr64  = jweStrVec[0];   // Encoded JWE Header
    const string& encCmkStr64  = jweStrVec[1];   // Encoded JWE Encrypted Content Master Key (CMK)
    const string& ivStr64      = jweStrVec[2];   // Encoded JWE Initialization Vector
    const string& encDataStr64 = jweStrVec[3];   // Encoded JWE Ciphertext (the actual target key)
    const string& macStr64     = jweStrVec[4];   // Encoded JWE Integrity Value

    // ---- process JWE header
    DLOG() << "\theader64 = " << headerStr64 << endl;
    const string headerJson(Base64::decodeUrlSafe(headerStr64));
    DLOG() << "\theader = " << headerJson << endl;
    if (headerJson.empty())
    {
        DLOG() << "CadmiumCrypto::unwrapJwe: JWE Header bad encoding\n";
        return CAD_ERR_BADENCODING; // TODO better error
    }
    const Variant headerVar = Variant::fromJSON(headerJson.c_str());

    // ---- validate JWE header 'alg'
    const string jweHeaderAlgStr = headerVar.mapValue<string>("alg");
    if (jweHeaderAlgStr.empty())
    {
        DLOG() << "CadmiumCrypto::unwrapJwe: JWE Header alg field not found\n";
        return CAD_ERR_UNKNOWN_ALGO; // TODO better error
    }
    if (jweHeaderAlgStr != "RSA-OAEP" && jweHeaderAlgStr != "A128KW" && jweHeaderAlgStr != "A256KW")
    {
        DLOG() << "CadmiumCrypto::unwrapJwe: JWE Header alg field must be RSA-OAEP, A128KW, or A256KW, found "
                << jweHeaderAlgStr << endl;
        return CAD_ERR_UNKNOWN_ALGO; // TODO better error
    }
    const Algorithm jweHeaderAlg = (jweHeaderAlgStr == "A128KW" || jweHeaderAlgStr == "A256KW") ? AES_KW : RSA_OAEP;

    // ---- validate JWE header 'enc'
    const string jweHeaderEncStr = headerVar.mapValue<string>("enc");
    // For AES key upwrap, 'enc' must be A128GCM (the spec also allows
    // A128CBC+HS256 but we don't support it)
    if (jweHeaderAlg == AES_KW && jweHeaderEncStr != "A128GCM")
    {
        DLOG() << "CadmiumCrypto::unwrapJwe: For AES key unwrap, the JWE Header "
                "'enc' field must be A128GCM\n";
        return CAD_ERR_UNKNOWN_ALGO; // TODO better error
    }
    // For RSA-OAEP key unwrap, 'enc' must be A128GCM or A256GCM
    if (jweHeaderAlg == RSA_OAEP && (jweHeaderEncStr != "A128GCM" && jweHeaderEncStr != "A256GCM"))
    {
        DLOG() << "CadmiumCrypto::unwrapJwe: For RSA_OAEP key unwrap, the JWE Header "
                "'enc' field must be A128GCM or A256GCM\n";
        return CAD_ERR_UNKNOWN_ALGO; // TODO better error
    }
    // get the key length to check the CMK length once it is decrypted
    const size_t jweCmkKeyLen = (jweHeaderEncStr == "A128GCM") ? 128/8 : 256/8;

    // ---- check the wrapping key
    if (!hasKey(wrappingKeyHandle))
        return CAD_ERR_BADKEYINDEX;
    if (!isUsageAllowed(wrappingKeyHandle, UNWRAP))
    {
        DLOG() << "CadmiumCrypto::unwrapJwe: operation disallowed by keyUsage\n";
        return CAD_ERR_KEY_USAGE;
    }
    Key key = keyMap_[wrappingKeyHandle];
    const Algorithm wrappingKeyAlg = toAlgorithm(key.algVar["name"].string());
    if (wrappingKeyAlg != jweHeaderAlg)
    {
        DLOG() << "CadmiumCrypto::unwrapJwe: Wrapping key algorithm does not match JWE header algorithm\n";
        return CAD_ERR_BADKEYNAME;  // FIXME, need better error
    }
    if (wrappingKeyAlg == RSA_OAEP && !key.pRsaContext.get())
    {
        // this should probably be an assert
        DLOG() << "CadmiumCrypto::unwrapJwe: RSA wrapping key not initialized\n";
        return CAD_ERR_BADKEYNAME;  // FIXME, need better error
    }
    if (wrappingKeyAlg == AES_KW && (extractIntFromString(jweHeaderAlgStr) != (int)key.key.size() * 8))
    {
        // this should probably be an assert
        DLOG() << "CadmiumCrypto::unwrapJwe: AES wrapping key has incompatible key size\n";
        return CAD_ERR_BADKEYNAME;  // FIXME, need better error
    }

    // ---- extract and decrypt the CMK
    const Vuc encCmkVuc64(encCmkStr64.begin(), encCmkStr64.end());
    const Vuc encCmkVuc(Base64::decodeUrlSafe(encCmkVuc64));
    DLOG() << "\nencrypted CMK = " << toB64String(encCmkVuc) << endl;
    Vuc cmkVuc;
    bool success;
    if (jweHeaderAlg == RSA_OAEP)
    {
        success = key.pRsaContext->privateDecrypt(encCmkVuc, cmkVuc, RsaContext::PKCS1_OAEP);
    }
    else // jweHeaderAlg == AES_KW
    {
        // Wes is seeing a problem where if the encrypted CMK is set very short,
        // he gets an out of memory error when OpenSSL's AES_unwrap_key is called
        // inside AesKeyWrapper.unwrap(). This does not happen on any other
        // machine so far. But anyway try to work around the problem by testing
        // the input encrypted CMK size against the expected decrypted CMK size,
        // the latter as read from the JWE header 'enc' field. For AES key
        // wrapping specifically, we know that the ciphertext size is always the
        // cleartext size + 8.
        if (encCmkVuc.size() < jweCmkKeyLen)
        {
            DLOG() << "encrypted CMK seems too short, aborting\n";
            return CAD_ERR_CIPHERERROR;
        }
        AesKeyWrapper aesKeyWrapper(key.key);
        success = aesKeyWrapper.unwrap(encCmkVuc, cmkVuc);
    }
    if (!success)
        return CAD_ERR_CIPHERERROR;
    DLOG() << "\nCMK = " << toB64String(cmkVuc) << endl;

    // ---- verify the CMK is the proper length (must be 128 or 256 bits), and
    // consistent with the JWE header "enc" field
    if (cmkVuc.size() != jweCmkKeyLen && cmkVuc.size() != 128/8 && cmkVuc.size() != 256/8)
    {
        DLOG() << "CadmiumCrypto::unwrapJwe: bad CMK length\n";
        return CAD_ERR_CIPHERERROR; // TODO better error
    }

    // ---- extract the initialization vector
    const Vuc ivVuc64(ivStr64.begin(), ivStr64.end());
    const Vuc ivVuc(Base64::decodeUrlSafe(ivVuc64));
    if (ivVuc.empty())
    {
        DLOG() << "CadmiumCrypto::unwrapJwe: empty IV\n";
        return CAD_ERR_BADARG; // TODO better error
    }
    DLOG() << "\nIV  = " << toB64String(ivVuc) << endl;

    // ---- extract the ciphertext
    const Vuc cipherTextVuc64(encDataStr64.begin(), encDataStr64.end());
    const Vuc cipherTextVuc(Base64::decodeUrlSafe(cipherTextVuc64));
    if (cipherTextVuc.empty())
    {
        DLOG() << "CadmiumCrypto::unwrapJwe: empty ciphertext\n";
        return CAD_ERR_BADARG; // TODO better error
    }
    DLOG() << "\nciphertext = " << toB64String(cipherTextVuc) << endl;

    // ---- extract the MAC
    const Vuc macVuc64(macStr64.begin(), macStr64.end());
    const Vuc macVuc(Base64::decodeUrlSafe(macVuc64));
    if (macVuc.empty())
    {
        DLOG() << "CadmiumCrypto::unwrapJwe: empty authentication tag\n";
        return CAD_ERR_BADARG; // TODO better error
    }
    DLOG() << "\nauthentication tag = " << toB64String(macVuc) << endl;

    // ---- construct the AAD
    string aadStr;
    aadStr.reserve(headerStr64.size() + encCmkStr64.size() + ivStr64.size() + 2);
    aadStr = headerStr64 + "." + encCmkStr64 + "." + ivStr64;
    const Vuc aadVuc(aadStr.begin(), aadStr.end());
    DLOG() << "\nAAD = " << aadStr << endl << endl;

    // ---- do the decrypt, if successfull clearText will contain the JWK
    AesGcmCipher aesGcmCipher(cmkVuc, ivVuc);
    Vuc clearTextVuc;
    success = aesGcmCipher.decrypt(cipherTextVuc, aadVuc, macVuc, clearTextVuc);
    DLOG() << "\ncleartext = " << toB64String(clearTextVuc) << endl;
    DLOG() << "cleartext = " << string(clearTextVuc.begin(), clearTextVuc.end()) << endl << endl;
    if (!success)
    {
        DLOG() << "CadmiumCrypto::unwrapJwe: aesGcmCipher.decrypt fail\n";
        return CAD_ERR_CIPHERERROR; // TODO better error
    }
    DLOG() << "Decrypt / Authentication success!!\n";

    // clearTextVuc contains the unwrapped JWK key to import

    // ---- import the JWK and we are done
    return importJwk(clearTextVuc, algVar, extractable, keyUsage, keyHandle);
}

CadErr CadmiumCrypto::CadmiumCryptoImpl::wrapJwe(uint32_t toBeWrappedKeyHandle,
        uint32_t wrappingKeyHandle, const Variant& wrappingAlgoObj,
        JweEncMethod jweEncMethod, string& wrappedKeyJcsStr64)
{
    if (!isInited_)
        return CAD_ERR_NOT_INITIALIZED;

    // http://www.w3.org/2012/webcrypto/wiki/KeyWrap_Proposal

    DLOG() << "CadmiumCrypto::wrapJwe:\n";

    // ---- Input checks

    // wrappingAlgoObj may be null. If not make sure it is a supported algorithm.
    // We support only RSA-OAEP and AES-KW algorithms
    Algorithm wrappingAlgoType = INVALID_ALGORITHM;
    if (!wrappingAlgoObj.isNull())
    {
        const string wrappingAlgoTypeStr = wrappingAlgoObj["name"].string();
        wrappingAlgoType = toAlgorithm(wrappingAlgoTypeStr);
        if (wrappingAlgoType != RSA_OAEP && wrappingAlgoType != AES_KW)
        {
            DLOG() << "CadmiumCrypto::wrapJwe: Only RSA-OAEP and AES-KW algorithms supported\n";
            return CAD_ERR_UNKNOWN_ALGO;    // FIXME: better error
        }
    }

    // verify the keys exist
    if (!hasKey(toBeWrappedKeyHandle) || !hasKey(wrappingKeyHandle))
    {
        DLOG() << "CadmiumCrypto::wrapJwe: key does not exist\n";
        return CAD_ERR_BADKEYINDEX;
    }

    // check the wrapping key
    if (!isUsageAllowed(wrappingKeyHandle, WRAP))
    {
        DLOG() << "CadmiumCrypto::wrapJwe: operation disallowed by keyUsage\n";
        return CAD_ERR_KEY_USAGE;
    }
    const Key wrappingKey = keyMap_[wrappingKeyHandle];
    const Algorithm wrappingKeyAlgoType = toAlgorithm(wrappingKey.algVar["name"].string());
    // if provided, the API alg must match the wrapping key's alg
    if (!wrappingAlgoObj.isNull() && (wrappingAlgoType != wrappingKeyAlgoType))
    {
        DLOG() << "CadmiumCrypto::wrapJwe: wrapping key and wrapping algorithm are inconsistent\n";
        return CAD_ERR_UNKNOWN_ALGO;    // FIXME: better error
    }
    const size_t wrappingKeyLengthBits = wrappingKey.key.size() * 8;
    switch (wrappingKeyAlgoType)
    {
        case RSA_OAEP:
        {
            // make sure the key has an RSA context already
            if (!wrappingKey.pRsaContext.get())
            {
                DLOG() << "CadmiumCrypto::wrapJwe: RSA-OAEP wrapping key not initialized\n";
                return CAD_ERR_UNKNOWN_ALGO;    // FIXME: better error
            }
            break;
        }
        case AES_KW:
        {
            // make sure the key is the right size for AES key wrap
            if (wrappingKeyAlgoType == AES_KW && wrappingKeyLengthBits != 128 && wrappingKeyLengthBits != 256)
            {
                DLOG() << "CadmiumCrypto::wrapJwe: AES wrapping key must be 128 or 256 bits\n";
                return CAD_ERR_UNKNOWN_ALGO;    // FIXME: better error
            }
            break;
        }
        default:
        {
            // wrapping key alg must be either RSA-OAEP or AES_KW
            DLOG() << "CadmiumCrypto::wrapJwe: Only RSA-OAEP and AES-KW algorithms supported\n";
            return CAD_ERR_UNKNOWN_ALGO;    // FIXME: better error
            break;  // not reached
        }
    }

    // ---- Construct JWE header
    string jweHeaderStr("{\"alg\":");
    if (wrappingKeyAlgoType == RSA_OAEP)
        jweHeaderStr += "\"RSA-OAEP\"";
    else    // wrappingKeyAlgoType == AES_KW
        jweHeaderStr += (wrappingKeyLengthBits == 128) ? "\"A128KW\"" : "\"A256KW\"";
    jweHeaderStr += ",\"enc\":";
    if (jweEncMethod == A128GCM)
        jweHeaderStr += "\"A128GCM\"}";
    else // jweEncMethod == A256GCM
        jweHeaderStr += "\"A256GCM\"}";
    DLOG() << "\njweHeader = " << jweHeaderStr << endl;
    const string jweHeaderStr64url(Base64::encodeUrlSafe(jweHeaderStr));
    DLOG() << "\njweHeader64url = " << jweHeaderStr64url << endl;
    const Vuc jweHeaderVuc64url(jweHeaderStr64url.begin(), jweHeaderStr64url.end());

    // ---- Generate a random Content Master Key (CMK)
    const int cmkKeyLenBytes = (jweEncMethod == A128GCM) ? 16 : 32;
    const Vuc cmkVuc(random::next(cmkKeyLenBytes));
    DLOG() << "\nCMK = " << toB64String(cmkVuc) << endl;

    // ---- Encrypt the CMK according to the wrapping algo type
    Vuc encCmkVuc;
    bool success;
    if (wrappingKeyAlgoType == RSA_OAEP)
    {
        success = wrappingKey.pRsaContext->publicEncrypt(cmkVuc, encCmkVuc,
                RsaContext::PKCS1_OAEP);
    }
    else // wrappingKeyAlgoType == AES_KW
    {
        AesKeyWrapper aesKeyWrapper(wrappingKey.key);
        success = aesKeyWrapper.wrap(cmkVuc, encCmkVuc);
    }
    if (!success)
        return CAD_ERR_CIPHERERROR;
    DLOG() << "\nencrypted CMK = " << toB64String(encCmkVuc) << endl;

    // ---- Generate a random 96-bit initialization vector (IV)
    const Vuc ivVuc(random::next(12));
    DLOG() << "\nIV  = " << toB64String(ivVuc) << endl;

    // ---- Construct the GCM "Additional Authenticated Data" parameter.
    // This is a concatenation of the JWE Header, the CMK, and the IV, each
    // base64url-encoded and separated with a '.'.
    const Vuc encCmkVuc64url(Base64::encodeUrlSafe(encCmkVuc));
    const Vuc ivVuc64url(Base64::encodeUrlSafe(ivVuc));
    Vuc aadVuc = jweHeaderVuc64url;
    aadVuc.reserve(jweHeaderVuc64url.size() + encCmkVuc64url.size() + ivVuc64url.size() + 2);
    aadVuc.push_back('.');
    aadVuc.insert(aadVuc.end(), encCmkVuc64url.begin(), encCmkVuc64url.end());
    aadVuc.push_back('.');
    aadVuc.insert(aadVuc.end(), ivVuc64url.begin(), ivVuc64url.end());
    DLOG() << "\nAAD = " << string(aadVuc.begin(), aadVuc.end()) << endl;

    // ---- Get a JKW representation of the key to be wrapped
    const Key toBeWrappedKey(keyMap_[toBeWrappedKeyHandle]);
    string jwkStr64;
    CadErr err = exportJwk(keyMap_[toBeWrappedKeyHandle], jwkStr64);
    if (err != CAD_ERR_OK)
        return err;
    const string jwkStr(Base64::decode(jwkStr64));
    DLOG() << "\nJWK to wrap = " << jwkStr << endl;

    // ---- Encrypt
    // Encrypt the cleartext JWK with AES GCM using the CMK as the
    // encryption key, the JWE Initialization Vector, and the AAD value
    // above, with a 128 bit "authentication tag" output
    AesGcmCipher aesGcmCipher(cmkVuc, ivVuc);
    const Vuc clearTextVuc(jwkStr.begin(), jwkStr.end());
    Vuc cipherTextVuc;
    Vuc macVuc;
    success = aesGcmCipher.encrypt(clearTextVuc, aadVuc, cipherTextVuc, macVuc);
    if (!success)
        return CAD_ERR_CIPHERERROR;
    DLOG() << "\nCiphertext = " << toB64String(cipherTextVuc) << endl;
    DLOG() << "\nMAC = " << toB64String(macVuc) << endl;

    // ---- Assemble the final representation
    // The Compact Serialization of this result is the concatenation of:
    // - the base64url-Encoded JWE Header
    // - the base64url-Encoded JWE Encrypted Key (CMK)
    // - the base64url-Encoded JWE Initialization Vector
    // - the base64url-Encoded JWE Ciphertext
    // - the base64url-Encoded JWE Integrity Value (Mac)
    // in that order, with the five strings being separated by four period
    // ('.') characters.

    // Already have the base64url-Encoded JWE Header in jweHeaderStr64url

    // the base64url-Encoded JWE Encrypted Key (CMK)
    const string encCmkStr64url(vucToStr64url(encCmkVuc));

    // the base64url-Encoded JWE Initialization Vector
    const string ivStr64url(vucToStr64url(ivVuc));

    // the base64url-Encoded JWE Ciphertext
    const string cipherTextStr64url(vucToStr64url(cipherTextVuc));

    // the base64url-Encoded JWE Integrity Value (Mac)
    const string macStr64url(vucToStr64url(macVuc));

    string wrappedKeyJcsStr;

#ifdef JWECS_WRAP_OUTPUT    // output JWE-CS format

    wrappedKeyJcsStr.reserve(
            jweHeaderStr64url.size()  +
            encCmkStr64url.size()     +
            ivStr64url.size()         +
            cipherTextStr64url.size() +
            macStr64url.size()        +
            4);
    wrappedKeyJcsStr =
            jweHeaderStr64url  + "." +
            encCmkStr64url     + "." +
            ivStr64url         + "." +
            cipherTextStr64url + "." +
            macStr64url;

#else   // output JWE-JS format

    //var jweJsData = latin1.parse(JSON.stringify({
    //    recipients:[{
    //        header:            jweDataAry[0],
    //        encrypted_key:     jweDataAry[1],
    //        integrity_value:   jweDataAry[4],
    //    }],
    //    initialization_vector: jweDataAry[2],
    //    ciphertext:            jweDataAry[3]

    VariantMap jsonVar;
    VariantArray recipientsVarAry;
    VariantMap recipientVar;
    recipientVar["header"] = jweHeaderStr64url;
    recipientVar["encrypted_key"] = encCmkStr64url;
    recipientVar["integrity_value"] = macStr64url;
    recipientsVarAry.push_back(recipientVar);
    jsonVar["recipients"] = recipientsVarAry;
    jsonVar["initialization_vector"] = ivStr64url;
    jsonVar["ciphertext"] = cipherTextStr64url;
    wrappedKeyJcsStr = Variant(jsonVar).toJSON();

#endif

    DLOG() << "\nFinal JWE = " << wrappedKeyJcsStr << endl << endl;

    wrappedKeyJcsStr64 = Base64::encode(wrappedKeyJcsStr);

    return CAD_ERR_OK;
}

CadErr CadmiumCrypto::CadmiumCryptoImpl::symKeyGen(const Variant& algVar,
        bool extractable, const vector<KeyUsage> keyUsage, uint32_t &keyHandle)
{
    if (!isInited_)
        return CAD_ERR_NOT_INITIALIZED;
    const Algorithm algType = toAlgorithm(algVar["name"].string());
    if (isAlgorithmRsa(algType))
    {
        DLOG() << "CadmiumCrypto::symKeyGen: ERROR: not a symmetric algorithm\n";
        return CAD_ERR_INTERNAL;    // FIXME better error
    }

    // make sure we have a params object
    if (!algVar.contains("params"))
    {
        DLOG() << "CadmiumCrypto::symKeyGen: ERROR: algorithm missing params field\n";
        return CAD_ERR_INTERNAL;    // FIXME better error
    }

    if (!reconcileAlgVsUsage(algType, keyUsage))
    {
        DLOG() << "CadmiumCrypto::symKeyGen: ERROR: inconsistent algorithm vs usage\n";
        return CAD_ERR_INTERNAL;    // FIXME better error
    }

    // get the key length
    int keyLengthBits;
    if (isAlgorithmAes(algType))
    {
        DLOG() << "\tAES generate key\n";

        // params is a AesKeyGenParams

        if (!algVar["params"].contains("length"))
        {
            DLOG() << "CadmiumCrypto::symKeyGen: ERROR: algorithm params missing length field\n";
            return CAD_ERR_INTERNAL;    // FIXME better error
        }

        // extract the key length
        keyLengthBits = algVar["params"].mapValue<int>("length");
        DLOG() << "\tkey length bits: " << keyLengthBits << endl;
    }
    else // (algType == CadmiumCrypto::HMAC)
    {
        DLOG() << "\tHMAC generate key\n";

        // paramsObj is a HmacParams

        if (!algVar["params"].contains("hash"))
        {
            DLOG() << "CadmiumCrypto::symKeyGen: ERROR: algorithm params missing hash algorithm field\n";
            return CAD_ERR_INTERNAL;    // FIXME better error
        }

        if (!algVar["params"]["hash"].contains("name"))
        {
            DLOG() << "CadmiumCrypto::symKeyGen: ERROR: algorithm params hash algorithm missing name field\n";
            return CAD_ERR_INTERNAL;    // FIXME better error
        }

        const Algorithm hashType = toAlgorithm(algVar["params"]["hash"].mapValue<string>("name"));

        // Deduce the required key length from the hash name. RFC4868 recommends
        // the key length be equal to the output length of the hash function.
        switch (hashType)
        {
            case CadmiumCrypto::SHA1:      keyLengthBits = 160;    break;
            case CadmiumCrypto::SHA224:    keyLengthBits = 224;    break;
            case CadmiumCrypto::SHA256:    keyLengthBits = 256;    break;
            case CadmiumCrypto::SHA384:    keyLengthBits = 384;    break;
            case CadmiumCrypto::SHA512:    keyLengthBits = 512;    break;
            default:
                DLOG() << "CadmiumCrypto::symKeyGen: ERROR: unknown HMAC inner hash algorithm\n";
                return CAD_ERR_INTERNAL;    // FIXME better error
        }
    }

    const Vuc randBytes = random::next((keyLengthBits + 7) / 8);
    keyHandle = nextKeyHandle_++;
    Key key(randBytes, shared_ptr<RsaContext>(), SECRET, extractable, algVar, keyUsage);
    keyMap_[keyHandle] = key;
    return CAD_ERR_OK;
}

CadErr CadmiumCrypto::CadmiumCryptoImpl::pbkdf2Derive(const string& saltStr64,
        uint32_t iterations, const base::Variant& prf, const string& password,
        const base::Variant& derivedAlgObj, bool extractable,
        const vector<KeyUsage> usage, uint32_t &keyHandle)
{
    // parm check
    if (saltStr64.empty() || !iterations || password.empty())
        return CAD_ERR_BADARG;

    const Vuc salt(str64toVuc(saltStr64));
    if (salt.empty())
        return CAD_ERR_BADARG;

    // PRF must be a SHA
    Algorithm hashType;
    if (prf.isString())
        hashType = toAlgorithm(prf.string());
    else
        hashType = toAlgorithm(prf["name"].string());
    if (hashType == CadmiumCrypto::INVALID_ALGORITHM)
    {
        DLOG() << "ERROR: CadmiumCrypto::pbkdf2Derive prf missing algorithm\n";
        return CAD_ERR_UNKNOWN_ALGO;
    }
    if (!isAlgorithmSha(hashType))
    {
        DLOG() << "ERROR: CadmiumCrypto::pbkdf2Derive prf must be SHA\n";
        return CAD_ERR_UNKNOWN_ALGO;
    }

    // validate derivedAlgObj; should be for symmetric key only
    const Algorithm derivedAlgType = toAlgorithm(derivedAlgObj["name"].string());
    if (!isAlgorithmAes(derivedAlgType) && !isAlgorithmHmac(derivedAlgType))
    {
        DLOG() << "ERROR: CadmiumCrypto::pbkdf2Derive derived alg must be AES or HMAC\n";
        return CAD_ERR_UNKNOWN_ALGO;
    }

    shared_ptr<const DigestAlgo> algo;
    switch(hashType)
    {
        case SHA1:      algo = DigestAlgo::SHA1();      break;
        case SHA224:    algo = DigestAlgo::SHA224();    break;
        case SHA256:    algo = DigestAlgo::SHA256();    break;
        case SHA384:    algo = DigestAlgo::SHA384();    break;
        case SHA512:    algo = DigestAlgo::SHA512();    break;
        default:        assert(false);                  break;
    }

    // FIXME: how to get key length?
    const uint32_t keyLen = 40;


    Pbkdf2 pbkdf2(algo);
    Vuc rawKey;
    bool success = pbkdf2.generate(salt, iterations, password, keyLen, rawKey);
    if (!success)
        return CAD_ERR_KEYDERIVE;

    // make the key
    keyHandle = nextKeyHandle_++;
    Key key(rawKey, shared_ptr<RsaContext>(), SECRET, extractable, derivedAlgObj, usage);
    keyMap_[keyHandle] = key;
    return CAD_ERR_OK;
}

CadErr CadmiumCrypto::CadmiumCryptoImpl::getKeyByName(const string keyName,
        uint32_t &keyHandle, string& metadata)
{
    NamedKeyMap::const_iterator it = namedKeyMap_.find(keyName);
    if (it == namedKeyMap_.end())
        return CAD_ERR_BADKEYNAME;
    keyHandle = it->second.keyHandle;
    metadata = it->second.id;
    return CAD_ERR_OK;
}

CadErr CadmiumCrypto::CadmiumCryptoImpl::getDeviceId(string& deviceId) const
{
    if (!isInited_)
        return CAD_ERR_NOT_INITIALIZED;
    deviceId = Base64::encode(pDeviceInfo_->getDeviceId());
    return CAD_ERR_OK;
}

CadErr CadmiumCrypto::CadmiumCryptoImpl::getSystemKeyHandle(uint32_t& systemKeyHandle) const
{
    if (!isInited_)
        return CAD_ERR_NOT_INITIALIZED;
    systemKeyHandle = systemKeyHandle_;
    return CAD_ERR_OK;
}

}} // namespace cadmium::crypto
