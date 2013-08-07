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
#ifndef CADMIUMCRYPTO_H_
#define CADMIUMCRYPTO_H_

#include <stdint.h>
#include <string>
#include <vector>
#include <memory>
#include <base/CadmiumErrors.h>
#include <base/Noncopyable.h>

namespace cadmium {

class IDeviceInfo;

namespace base { class Variant; }

namespace crypto {

/** Low-level crypto functions for Cadmium / NfWebCrypto.
 * This class provides the  operations required to implement the Web Crypto API
 * and algorithm set required by Cadmium. It does not attempt to implement
 * everything in the Web Crypto spec. Raw keying material and RSA/Diffie-Hellman
 * session info is stored in memory and never exposed to the client, behind a
 * key handle paradigm. No persistent storage is used, the key store is empty
 * at creation.
 */
class CadmiumCrypto : base::Noncopyable
{
public:

    CadmiumCrypto(IDeviceInfo * pDeviceInfo);

    ~CadmiumCrypto();

    /** Initialize the instance.
     * This method performs internal initialization of the CadmiumCrypto
     * instance. It must be called after construction, before any other methods
     * are used.
     * @param[in] prngSeed Vector of random bytes with which to seed OpenSSL's PRNG.
     *   Must be of length MIN_SEED_LEN or greater.
     * @return CadErr, CAD_ERR_OK if no error
     */
    typedef std::vector<unsigned char> Vuc;
    static const size_t MIN_SEED_LEN = 512 / 8;
    CadErr init(const Vuc& prngSeed);

    /** Adds entropy to the OpenSSL PRNG.
     * Some implementations like PPAPI feature a sandbox that blocks OpenSSL's
     * internal mechanism to add entropy to its PRNG. This method provides a way
     * to manually add entropy after the instance is constructed to make up for
     * that deficiency. For example, with PPAPI entropy to add can be obtained
     * with a mainthread call to PPB_Crypto_Dev::GetRandomBytes().
     * @param[in] entropyBytes vector of entropy bytes, base64-encoded
     */
    void addEntropy(const std::string& entropyBytes);

    //---------------- Key Store ---------------------------------------------//

    /** Import a key
     * This method imports a key into the local key store.
     * @param[in] format The format of the keyData containing the key
     * @param[in] keyData The data containing the key, base64-encoded.
     * @param[in] algObj The full details about the key generation algorithm.
     * @param[in] extractable In. Whether or not the raw keying material may be
     *     exported by the application.
     * @param[in] keyUsage A vector of KeyUsage, indicating what operations may
     *     be used with this key.
     * @param[out] keyHandle The handle of the imported key in the key store.
     */
    enum KeyFormat
    {
        RAW,    //< An unformatted sequence of bytes. Intended for secret keys.
        PKCS8,  //< The DER encoding of the PrivateKeyInfo structure from RFC 5208.
        SPKI,   //< The DER encoding of the SubjectPublicKeyInfo structure from RFC 5280.
        JWK,    //< The key is represented as JSON according to the JSON Web Key format.
        INVALID_KEYFORMAT
    };
    enum Algorithm
    {
        HMAC,
        AES_CBC,
        AES_GCM,
        AES_CTR,
        RSAES_PKCS1_V1_5,
        RSASSA_PKCS1_V1_5,
        RSA_OAEP,
        SHA1,
        SHA224,
        SHA256,
        SHA384,
        SHA512,
        AES_KW,
        DH,
        PBKDF2,
        SYSTEM,
        INVALID_ALGORITHM
    };
    enum KeyUsage {ENCRYPT, DECRYPT, SIGN, VERIFY, DERIVE, WRAP, UNWRAP};
    CadErr importKey(KeyFormat format, const std::string& keyData,
        const base::Variant& algVar, bool extractable,
        const std::vector<KeyUsage>& keyUsage, uint32_t& keyHandle);

    /** Export a key
     * This method exports a key from the local key store. Only keys that are
     * marked extractable may be exported.
     * @param[in] keyHandle The handle of the key to export.
     * @param[in] format The desired format of the exported key data.
     * @param[out] keyData The data containing the key in the desired format,
     *     base64-encoded.
     */
    CadErr exportKey(uint32_t keyHandle, KeyFormat format, std::string& keyData);

    /** Get key info
     * This method reports information about a key in the local key store.
     * @param[in] keyHandle The handle of the key
     * @param[out] type The key type
     * @param[in] extractable Whether the key is marked as extractable
     * @param[out] algVar The full details about the key algorithm
     * @param[out] usage The intended uses of the key, may be empty
     */
    enum KeyType {SECRET, PUBLIC, PRIVATE};
    CadErr getKeyInfo(uint32_t keyHandle, KeyType& type, bool& extractable,
            base::Variant& algVar, std::vector<KeyUsage>& usage) const;

    //---------------- Digest ------------------------------------------------//

    /** Compute the message digest of the input data.
     * This method computes a SHA hash of the input data.
     * @param[in] algorithm The SHA algorithm to use
     * @param[in] data The data to hash, base64-encoded
     * @param[out] digest The result of the SHA computation, base64-encoded
     * @return CadErr, CAD_ERR_OK if no error
     */
    CadErr digest(Algorithm algorithm, const std::string& data, std::string& digest);

    //---------------- Encrypt / Decrypt -------------------------------------//

    /** AES-CBC encrypt data using a key in the key cache.
     * This method encrypts / decrypts input data with AES CBC, using a key in
     * the key cache indicated by the input key handle.
     * @param[in] keyHandle The handle of the desired key in the key cache.
     * @param[in] ivIn The initialization vector, base64-encoded
     * @param[in] dataIn Input data, base64-encoded
     * @param[in] cipherOp Which operation to perform
     * @param[out] dataOut Output data, base64-encoded
     * @return CadErr, CAD_ERR_OK if no error
     */
    enum CipherOp {DOENCRYPT, DODECRYPT};
    CadErr aesCbc(uint32_t keyHandle, const std::string& ivIn,
            const std::string& dataIn, CipherOp cipherOp, std::string& dataOut);

    /** AES-GCM encrypt data using a key in the key cache.
     * This method encrypts or decrypts input data with the AES-GCM authenticated
     * cipher, using the key in the key cache indicated by the input key handle.
     * The authentication tag is concatenated to the end of the ciphertext. When
     * decrypting if authentication fails, this method returns CAD_ERR_CIPHERERROR
     * and dataOut will be empty.
     * @paramp[in] keyHandle The handle of the key in the key cache.
     * @param[in] ivIn The initialization vector, base64-encoded
     * @param[in] dataIn Input data, base64-encoded
     * @param[in] aadIn Additional authenticated data, base64-encoded
     * @param[in] taglen The length in bits of the computed authentication tag, 0-128
     * @param[in] cipherOp Which operation to perform
     * @param[out] dataOut Output data, base64-encoded
     * @return CadErr, CAD_ERR_OK if no error
     */
    CadErr aesGcm(uint32_t keyHandle, const std::string& ivIn, const std::string& dataIn,
            const std::string& aadIn, uint8_t taglen, CipherOp cipherOp,
            std::string& dataOut);

    /** RSAES-PKCS1-v1_5 encrypt data using a key in the key cache.
     * This method encrypts input data with RSAES-PKCS1-v1_5, using a key in the
     * key cache indicated by the input key handle. The key must be an RSA key.
     * @param[in] keyHandle The handle of the desired RSA key in the key cache.
     * @param[in] dataIn The data to encrypt, base64-encoded
     * @param[in] cipherOp Which operation to perform
     * @param[out] dataOut The encrypted data, base64-encoded
     * @return CadErr, CAD_ERR_OK if no error
     */
    CadErr rsaCrypt(uint32_t keyHandle, const std::string& dataIn,
            CipherOp cipherOp, std::string& dataOut);

    //---------------- HMAC --------------------------------------------------//

    /** Compute the HMAC signature of the input data
     * This method computes the HMAC of the input data, using the specified
     * SHA inner hash and using the key indicated by the provided key handle.
     * @param[in] keyHandle The handle of the key to use when computing the HMAC
     * @param[in] shaAlgo The inner hash algorithm to use
     * @param[in] opUsage The usage of the operation to be performed (SIGN or VERIFY)
     * @param[in] data The data to HMAC, base64-encoded
     * @param[out] hmac The result of the HMAC operation, base64-encoded
     * @return CadErr, CAD_ERR_OK if no error
     */
    CadErr hmac(uint32_t keyHandle, Algorithm shaAlgo, KeyUsage opUsage,
            const std::string& data, std::string& hmac);

    //---------------- RSA ---------------------------------------------------//

    /** Generate an RSA public/private key pair
     * This method computes an RSA public/private key pair
     * @param algVar In. The full details about the key gen algorithm, including
     *     the public exponent and modulus length.
     * @param[in] extractable Whether or not the raw key material may be exported
     * @param[in] keyUsage The allowed usages of the keys
     * @param[out] pubKeyHandle The handle of the generated public key in the key map
     * @param[out] privKeyHandle The handle of the generated private key in the key map
     * @return CadErr, CAD_ERR_OK if no error
     */
    CadErr rsaKeyGen(const base::Variant& algVar, bool extractable,
            std::vector<KeyUsage> keyUsage, uint32_t& pubKeyHandle,
            uint32_t& privKeyHandle);

    /** RSA sign a block of data
     * This method computes the RSASSA-PKCS1-v1_5 signature of a block of data,
     * using the specified key and inner hash.
     * @param[in] keyHandle The handle of the key to use
     * @param[in] shaAlgo The inner message digest algorithm to use
     * @param[in] data The data over which to compute the signature, base64-encoded
     * @param[out] sig The computed signature, base64-encoded
     * @return CadErr, CAD_ERR_OK if no error
     */
    CadErr rsaSign(uint32_t keyHandle, Algorithm shaAlgo, const std::string& data,
            std::string& sig);

    /** RSA verify a block of data
     * This method computes the RSASSA-PKCS1-v1_5 signature of a block of data,
     * using the specified key and inner hash, and compares it to the provided
     * signature.
     * @param[in] keyHandle The handle of the key to use
     * @param[in] shaAlgo The inner message digest algorithm to use
     * @param[in] data The data over which to compute the signature, base64-encoded
     * @param[in] sig The data signature, base64-encoded
     * @param[out] isVerified True if the computed signature of the data matched
     *   the provided signature, otherwise false
     * @return CadErr, CAD_ERR_OK if no error
     */
    CadErr rsaVerify(uint32_t keyHandle, Algorithm shaAlgo, const std::string& data,
            const std::string& sig, bool& isVerified);

    //---------------- Diffie-Hellman ----------------------------------------//

    /** Generate a Diffie-Hellman public/private key pair
     * This method computes DH public/private key pair
     * @param[in] algVar The full details about the key gen algorithm, including
     *     the prime and generator values
     * @param[in] extractable Whether or not the raw key material may be exported
     * @param[in] keyUsage The allowed usages of the keys
     * @param[out] pubKeyHandle The handle of the generated public key in the key map
     * @param[out] privKeyHandle The handle of the generated private key in the key map
     * @return CadErr, CAD_ERR_OK if no error
     */
    CadErr dhKeyGen(const base::Variant& algVar, bool extractable,
            std::vector<KeyUsage> keyUsage, uint32_t& pubKeyHandle,
            uint32_t& privKeyHandle);

    /** Derive a shared private key
     * This method computes a shared private key using a baseKey produced by
     * dhKeyGen() plus the public key from the remote peer who has previously
     * obtained the public baseKey.
     * @param[in] baseKeyHandle The handle of the key that started the DH
     *   exchange, produced by a call to dhKeyGen
     * @param[in] peerPublicKeyData The raw public key received from the remote
     *   peer, base64-encoded
     * @param[in] derivedAlgObj The full details about the algorithm to be
     *   associated with the derived key
     * @param[in] extractable Whether or not the raw key material of the derived
     *   key may be exported
     * @param[in] keyUsage The allowed usages of the derived key
     * @param[out] keyHandle The handle of the derived key in the key map
     * @return CadErr, CAD_ERR_OK if no error
     */
    CadErr dhDerive(uint32_t baseKeyHandle, const std::string& peerPublicKeyData,
            const base::Variant& derivedAlgObj, bool extractable,
            std::vector<KeyUsage> keyUsage, uint32_t& keyHandle);

    //---------------- Symmetric Key Generation -----------------------------//
    /** Generate a symmetric key
     * This method generates a single random key and places it in the key store.
     * @param[in] algVar The full details about the key generation algorithm.
     * @param[in] extractable Whether the key should be marked as extractable
     * @param[in] usage The intended uses of the generated key
     * @param[out] jeyHandle The handle of the resulting key in the key store.
     * @return CadErr, CAD_ERR_OK if no error
     */
    CadErr symKeyGen(const base::Variant& algVar, bool extractable,
            const std::vector<KeyUsage> keyUsage, uint32_t &keyHandle);

    //---------------- Password-Based Key Derivation -------------------------//
    /** Generate a symmetric key based on a password/phrase
     * This method generates a single key from a password/phrase and places it
     * in the key store.
     * @param[in] salt Cryptographic salt, base64-encoded
     * @param[in] iterations The number of iterations desired
     * @param[in] prf A pseudorandom function of two parameters, only HMAC allowed
     * @param[in] password The passphrase, base64-encoded
     * @param[in] derivedAlgObj The full details about the algorithm to be
     *   associated with the derived key
     * @param[in] extractable Whether or not the raw key material of the derived
     *   key may be exported
     * @param[in] usage The intended uses of the derived key
     * @param[out] keyHandle The handle of the resulting key in the key store.
     * @return CadErr, CAD_ERR_OK if no error
     */
    CadErr pbkdf2Derive(const std::string& salt, uint32_t iterations,
            const base::Variant& prf, const std::string& password,
            const base::Variant& derivedAlgObj, bool extractable,
            const std::vector<KeyUsage> usage, uint32_t &keyHandle);

    //---------------- Key Discovery -----------------------------------------//
    /** Get a pre-provisioned named symmetric key
     * This method retrieves a pre-provisioned symmetric key by name from the
     * key store. Note that pre-provisioned keys are associated with a script
     * origin, so a key will not be present in the key store if the current
     * origin and origin of the pre-provisioned key are inconsistent.
     * see http://www.w3.org/TR/webcrypto-key-discovery/
     * @param[in] keyName The name of the key to retrieve
     * @param[in] keyHandle The handle of the resulting key in the key store.
     * @param[out] metadata Meta data associated with the named key
     * @return CadErr, CAD_ERR_OK if no error
     */
    CadErr getKeyByName(const std::string keyName, uint32_t &keyHandle, std::string& metadata);

    //---------------- Key Wrapping-------------------------------------------//

    /** Unwrap a JWE-wrapped key
     * This method unwraps a JWE-wrapped key as described in
     * draft-ietf-jose-json-web-encryption-08. This input JWE may be in either
     * the JSON or Compact Serialization format. The result is the unwrapped key
     * in the key store, which is referred to by the output keyHandle when later
     * performing other crypto operations. This method will report an error if
     * the unwrap fails for any reason, including failing the integrity check.
     * @param[in] jweData The base64-encoded wrapped key in JWE-JS or JWE-CS
     * format. Specifically, a wrapped key contains the following components
     *       Base64Url-encoded JWE Header,
     *       Base64Url-encoded JWE Encrypted Content Master Key (CMK),
     *       Base64Url-encoded JWE Initialization Vector,
     *       Base64Url-encoded JWE Ciphertext (the actual target key)
     *       Base64Url-encoded JWE Integrity Value,
     *     Encoding used in this string is URL-SAFE base64 UTF8 as mandated by
     *     the JWE spec. Note that this differs from the standard base64
     *     encoding used by the rest of this API.
     * @param[in] wrappingKeyHandle Handle of the key in the keystore with
     *     which to decrypt the CMK. This will be typically the RSA private key
     *     corresponding to the public key that encrypted the CMK.
     * @param[in] algVar In case the unwrapped JDK does not have the 'alg'
     *     field inside it, use this value; otherwise ignore
     * @param[in] extractable In case the unwrapped JWK does not have the
     *     'extractable' field inside it, use this value; otherwise the
     *     unwrapped key will have its extractable value set to a logical OR
     *     this and the extractable value inside the JWK.
     * @param[in] keyUsage In case the unwrapped JDK does not have the 'use'
     *     field inside it, use this value; otherwise ignore
     * @param[out] keyHandle The handle of the unwrapped key in the keystore.
     * @return CadErr, CAD_ERR_OK if no error
     */
    CadErr unwrapJwe(const std::string& jweData, uint32_t wrappingKeyHandle,
            const base::Variant& algVar, bool extractable,
            const std::vector<KeyUsage>& keyUsage, uint32_t& keyHandle);

    /** JWE-wrap an existing key
     * This method wraps an existing key in the keystore according to the rules
     * in draft-ietf-jose-json-web-encryption-08, using an existing wrapping key
     * also in the keystore. The result is a base-64 encoded JWE-JS string.
     * @param[in] toBeWrappedKeyHandle The handle of the key to be wrapped
     * @param[in] wrappingKeyHandle The handle of the key to use in during the
     *     key wrap process.
     * @param[in] wrappingAlgoObj The encryption algorithm to be applied to the
     *    Content Master Key (CMK) during the wrapping process. This must be
     *    consistent with the algorithm associated with wrappingKeyHandle.
     *    Only RSA-OAEP and AES-KW algorithms are supported.
     * @param[in] wrappingEnc The algorithm to apply cleartext data. For AES-KW,
     *    only A128GCM is supported, while RSA-OAEP supports only A128GCM and
     *    A256GCM.
     * @param[out] wrappedKeyJcs The base64-encoded wrapped key in the specific
     *    format described in JWE-JS spec
     * @return CadErr, CAD_ERR_OK if no error
     */
    enum JweEncMethod {A128GCM, A256GCM};
    CadErr wrapJwe(uint32_t toBeWrappedKeyHandle, uint32_t wrappingKeyHandle,
            const base::Variant& wrappingAlgoObj, JweEncMethod jweEncMethod,
            std::string& wrappedKeyJcs);

    //---------------- NON Web Crypto APIs------------------------------------//

    CadErr getDeviceId(std::string& deviceId) const;

    CadErr getSystemKeyHandle(uint32_t& systemKeyHandle) const;

private:
    // Note, to minimize client dependencies and hide details, this class is a
    // compiler firewall in front of the real code inside CadmiumCryptoImpl.
    class CadmiumCryptoImpl;
    std::auto_ptr<CadmiumCryptoImpl> impl_;
};

// Utility functions
std::string toString(CadmiumCrypto::Algorithm algorithm);
std::string toString(const std::vector<CadmiumCrypto::KeyUsage>& kusage);
std::string toString(CadmiumCrypto::KeyType keyType);
std::string toString(CadmiumCrypto::KeyUsage keyUsage);
CadmiumCrypto::Algorithm toAlgorithm(const std::string& algorithmStr);
bool isAlgorithmRsa(CadmiumCrypto::Algorithm algorithm);
bool isAlgorithmAes(CadmiumCrypto::Algorithm algorithm);
bool isAlgorithmHmac(CadmiumCrypto::Algorithm algorithm);
bool isAlgorithmSha(CadmiumCrypto::Algorithm algorithm);
bool isAlgorithmDh(CadmiumCrypto::Algorithm algorithm);

}}   // namespace cadmium::crypto

#endif // CADMIUMCRYPTO_H_
