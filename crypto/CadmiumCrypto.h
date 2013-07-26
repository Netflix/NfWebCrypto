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
     * @param prngSeed Vector of random bytes with which to seed OpenSSL's PRNG.
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
     * @param entropyBytes vector of entropy bytes, base64-encoded
     */
    void addEntropy(const std::string& entropyBytes);

    //---------------- Key Store ---------------------------------------------//

    /** Import a key
     * This method imports a key into the local key store.
     * @param format In. The format of the keyData containing the key
     * @param keyData In. The data containing the key, base64-encoded.
     * @param algObj In. The full details about the key generation algorithm.
     * @param extractable In. Whether or not the raw keying material may be
     *     exported by the application.
     * @param keyUsage In. A vector of KeyUsage, indicating what operations may
     *     be used with this key.
     * @param keyHandle Out. The handle of the imported key in the key store.
     * @param keyType Out. The type of the key, deduced from format and keyData
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
        SYSTEM,
        INVALID_ALGORITHM
    };
    enum KeyType {SECRET, PUBLIC, PRIVATE};
    enum KeyUsage {ENCRYPT, DECRYPT, SIGN, VERIFY, DERIVE, WRAP, UNWRAP};
    CadErr importKey(KeyFormat format, const std::string& keyData,
        const base::Variant& algVar, bool extractable,
        const std::vector<KeyUsage>& keyUsage,
        uint32_t& keyHandle, KeyType& keyType);

    /** Export a key
     * This method exports a key from the local key store. Only keys that are
     * marked extractable may be exported.
     * @param keyHandle In. The handle of the key to export.
     * @param format In. The desired format of the exported key data.
     * @param keyData Out. The data containing the key in the desired format,
     *     base64-encoded.
     */
    CadErr exportKey(uint32_t keyHandle, KeyFormat format, std::string& keyData);

    /** Get key info
     * This method reports information about a key in the local key store.
     * @param keyHandle In. The handle of the key
     * @param type Out. The key type
     * @param extractable Out. Whether the key is marked as extractable
     * @param algVar Out. The full details about the key algorithm
     * @param usage Out. The intended uses of the key, may be empty
     */
    CadErr getKeyInfo(uint32_t keyHandle, KeyType& type, bool& extractable,
            base::Variant& algVar, std::vector<KeyUsage>& usage) const;

    //---------------- Digest ------------------------------------------------//

    /** Compute the message digest of the input data.
     * This method computes a SHA hash of the input data.
     * @param algorithm In. The SHA algorithm to use
     * @param data In. The data to hash, base64-encoded
     * @param digest Out. The result of the SHA computation, base64-encoded
     * @return CadErr, CAD_ERR_OK if no error
     */
    CadErr digest(Algorithm algorithm, const std::string& data, std::string& digest);

    //---------------- Encrypt / Decrypt -------------------------------------//

    /** AES-CBC encrypt data using a key in the key cache.
     * This method encrypts / decrypts input data with AES CBC, using a key in
     * the key cache indicated by the input key handle.
     * @param keyHandle In. The handle of the desired key in the key cache.
     * @param ivIn In. The initialization vector, base64-encoded
     * @param dataIn In. Input data, base64-encoded
     * @param cipherOp In. Which operation to perform
     * @param dataOut Out. Output data, base64-encoded
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
     * @param keyHandle In. The handle of the key in the key cache.
     * @param ivIn In. The initialization vector, base64-encoded
     * @param dataIn In. Input data, base64-encoded
     * @param aadIn In. Additional authenticated data, base64-encoded
     * @param taglen In. The length in bits of the computed authentication tag, 0-128
     * @param cipherOp In. Which operation to perform
     * @param dataOut Out. Output data, base64-encoded
     * @return CadErr, CAD_ERR_OK if no error
     */
    CadErr aesGcm(uint32_t keyHandle, const std::string& ivIn, const std::string& dataIn,
            const std::string& aadIn, uint8_t taglen, CipherOp cipherOp,
            std::string& dataOut);

    /** RSAES-PKCS1-v1_5 encrypt data using a key in the key cache.
     * This method encrypts input data with RSAES-PKCS1-v1_5, using a key in the
     * key cache indicated by the input key handle. The key must be an RSA key.
     * @param keyHandle In. The handle of the desired RSA key in the key cache.
     * @param dataIn In. The data to encrypt, base64-encoded
     * @param cipherOp In. Which operation to perform
     * @param dataOut Out. The encrypted data, base64-encoded
     * @return CadErr, CAD_ERR_OK if no error
     */
    CadErr rsaCrypt(uint32_t keyHandle, const std::string& dataIn,
            CipherOp cipherOp, std::string& dataOut);

    //---------------- HMAC --------------------------------------------------//

    /** Compute the HMAC signature of the input data
     * This method computes the HMAC of the input data, using the specified
     * SHA inner hash and using the key indicated by the provided key handle.
     * @param keyHandle In. The handle of the key to use when computing the HMAC
     * @param shaAlgo In. The inner hash algorithm to use
     * @param opUsage In. The usage of the operation to be performed (SIGN or VERIFY)
     * @param data In. The data to HMAC, base64-encoded
     * @param hmac Out. The result of the HMAC operation, base64-encoded
     * @return CadErr, CAD_ERR_OK if no error
     */
    CadErr hmac(uint32_t keyHandle, Algorithm shaAlgo, KeyUsage opUsage,
            const std::string& data, std::string& hmac);

    //---------------- RSA ---------------------------------------------------//

    /** Generate an RSA public/private key pair
     * This method computes an RSA public/private key pair
     * @param algVar In. The full details about the key gen algorithm, including
     *     the public exponent and modulus length.
     * @param extractable In. Whether or not the raw key material may be exported
     * @param keyUsage In. The allowed usages of the keys
     * @param pubKeyHandle Out. The handle of the generated public key in the key map
     * @param privKeyHandle Out. The handle of the generated private key in the key map
     * @return CadErr, CAD_ERR_OK if no error
     */
    CadErr rsaKeyGen(const base::Variant& algVar, bool extractable,
            std::vector<KeyUsage> keyUsage, uint32_t& pubKeyHandle,
            uint32_t& privKeyHandle);

    /** RSA sign a block of data
     * This method computes the RSASSA-PKCS1-v1_5 signature of a block of data,
     * using the specified key and inner hash.
     * @param keyHandle In. The handle of the key to use
     * @param shaAlgo In. The inner message digest algorithm to use
     * @param data In. The data over which to compute the signature, base64-encoded
     * @param sig Out. The computed signature, base64-encoded
     * @return CadErr, CAD_ERR_OK if no error
     */
    CadErr rsaSign(uint32_t keyHandle, Algorithm shaAlgo, const std::string& data,
            std::string& sig);

    /** RSA verify a block of data
     * This method computes the RSASSA-PKCS1-v1_5 signature of a block of data,
     * using the specified key and inner hash, and compares it to the provided
     * signature.
     * @param keyHandle In. The handle of the key to use
     * @param shaAlgo In. The inner message digest algorithm to use
     * @param data In. The data over which to compute the signature, base64-encoded
     * @param sig In. The data signature, base64-encoded
     * @param isVerified Out. True if the computed signature of the data matched
     * the provided signature, otherwise false
     * @return CadErr, CAD_ERR_OK if no error
     */
    CadErr rsaVerify(uint32_t keyHandle, Algorithm shaAlgo, const std::string& data,
            const std::string& sig, bool& isVerified);

    //---------------- Diffie-Hellman ----------------------------------------//

    /** Generate a Diffie-Hellman public/private key pair
     * This method computes DH public/private key pair
     * @param algVar In. The full details about the key gen algorithm, including
     *     the prime and generator values
     * @param extractable In. Whether or not the raw key material may be exported
     * @param keyUsage In. The allowed usages of the keys
     * @param pubKeyHandle Out. The handle of the generated public key in the key map
     * @param privKeyHandle Out. The handle of the generated private key in the key map
     * @return CadErr, CAD_ERR_OK if no error
     */
    CadErr dhKeyGen(const base::Variant& algVar, bool extractable,
            std::vector<KeyUsage> keyUsage, uint32_t& pubKeyHandle,
            uint32_t& privKeyHandle);

    /** Derive a shared private key
     * This method computes a shared private key using a baseKey produced by
     * dhKeyGen() plus the public key from the remote peer who has previously
     * obtained the public baseKey.
     * @param baseKeyHandle In. The handle of the key that started the DH
     *   exchange, produced by a call to dhKeyGen
     * @param peerPublicKeyData In. The raw public key received from the remote
     *   peer, base64-encoded
     * @param derivedAlgObj In. The full details about the algorithm to be
     *   associated with the derived key
     * @param extractable In. Whether or not the raw key material of the derived
     *   key may be exported
     * @param keyUsage In. The allowed usages of the derived key
     * @param keyHandle Out. The handle of the derived key in the key map
     * @return CadErr, CAD_ERR_OK if no error
     */
    CadErr dhDerive(uint32_t baseKeyHandle, const std::string& peerPublicKeyData,
            const base::Variant& derivedAlgObj, bool extractable,
            std::vector<KeyUsage> keyUsage, uint32_t& keyHandle);

    //---------------- Symmnetric Key Generation -----------------------------//
    /** Generate a symmetric key
     * This method generates a single random key and places it in the key store.
     * @param algVar In. The full details about the key generation algorithm.
     * @param extractable In. Whether the key should be marked as extractable
     * @param usage In. The intended uses of the key
     * @param jeyHandle Out. The handle of the resulting key in the key store.
     */
    CadErr symKeyGen(const base::Variant& algVar, bool extractable,
            const std::vector<KeyUsage> keyUsage, uint32_t &keyHandle);

    //---------------- Key Wrapping-------------------------------------------//

    /** Unwrap a JWE-wrapped key
     * This method unwraps a JWE-wrapped key as described in
     * draft-ietf-jose-json-web-encryption-08. This input JWE may be in either
     * the JSON or Compact Serialization format. The result is the unwrapped key
     * in the key store, which is referred to by the output keyHandle when later
     * performing other crypto operations. This method will report an error if
     * the unwrap fails for any reason, including failing the integrity check.
     * @param jweData In. The base64-encoded wrapped key in JWE-JS or JWE-CS
     * format. Specifically, a wrapped key contains the following components
     *       Base64Url-encoded JWE Header,
     *       Base64Url-encoded JWE Encrypted Content Master Key (CMK),
     *       Base64Url-encoded JWE Initialization Vector,
     *       Base64Url-encoded JWE Ciphertext (the actual target key)
     *       Base64Url-encoded JWE Integrity Value,
     *     Encoding used in this string is URL-SAFE base64 UTF8 as mandated by
     *     the JWE spec. Note that this differs from the standard base64
     *     encoding used by the rest of this API.
     * @param wrappingKeyHandle In. Handle of the key in the keystore with
     *     which to decrypt the CMK. This will be typically the RSA private key
     *     corresponding to the public key that encrypted the CMK.
     * @param algVar In. In case the unwrapped JDK does not have the 'alg'
     *     field inside it, use this value; otherwise ignore
     * @param extractable In. In case the unwrapped JWK does not have the
     *     'extractable' field inside it, use this value; otherwise the
     *     unwrapped key will have its extractable value set to a logical OR
     *     this and the extractable value inside the JWK.
     * @param keyUsage In. In case the unwrapped JDK does not have the 'use'
     *     field inside it, use this value; otherwise ignore
     * @param keyHandle Out. The handle of the unwrapped key in the keystore.
     */
    CadErr unwrapJwe(const std::string& jweData, uint32_t wrappingKeyHandle,
            const base::Variant& algVar, bool extractable,
            const std::vector<KeyUsage>& keyUsage, uint32_t& keyHandle);

    /** JWE-wrap an existing key
     * This method wraps an existing key in the keystore according to the rules
     * in draft-ietf-jose-json-web-encryption-08, using an existing wrapping key
     * also in the keystore. The result is a base-64 encoded JWE-JS string.
     * @param toBeWrappedKeyHandle In. The handle of the key to be wrapped
     * @param wrappingKeyHandle In. The handle of the key to use in during the
     *     key wrap process.
     * @param wrappingAlgoObj In. The encryption algorithm to be applied to the
     *    Content Master Key (CMK) during the wrapping process. This must be
     *    consistent with the algorithm associated with wrappingKeyHandle.
     *    Only RSA-OAEP and AES-KW algorithms are supported.
     * @param wrappingEnc In. The algorithm to apply cleartext data. For AES-KW,
     *    only A128GCM is supported, while RSA-OAEP supports only A128GCM and
     *    A256GCM.
     * @param wrappedKeyJcs Out. The base64-encoded wrapped key in the specific
     *    format described in JWE-JS spec
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
