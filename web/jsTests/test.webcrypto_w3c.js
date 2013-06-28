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

(function () {
    "use strict";

    // get "crypto" from the right namespace
    var crypto = nfCrypto;
    var cryptoSubtle = crypto.subtle;
    
    function objCompare(a, b) {
        return Object.keys(a).every(function(k) {
            return a[k] === b[k];
        });
    }

    test(function() {
        assert_not_equals(crypto, undefined, "crypto exists");
        assert_equals(typeof crypto.getRandomValues, "function", "crypto.getRandomValues exists");
        assert_not_equals(cryptoSubtle, undefined, "crypto.subtle exists");
        assert_equals(typeof cryptoSubtle.encrypt,     "function", "crypto.subtle.encrypt exists");
        assert_equals(typeof cryptoSubtle.decrypt,     "function", "crypto.subtle.decrypt exists");
        assert_equals(typeof cryptoSubtle.sign,        "function", "crypto.subtle.sign exists");
        assert_equals(typeof cryptoSubtle.verify,      "function", "crypto.subtle.verify exists");
        assert_equals(typeof cryptoSubtle.digest,      "function", "crypto.subtle.digest exists");
        assert_equals(typeof cryptoSubtle.generateKey, "function", "crypto.subtle.generateKey exists");
        assert_equals(typeof cryptoSubtle.deriveKey,   "function", "crypto.subtle.deriveKey exists");
        assert_equals(typeof cryptoSubtle.exportKey,   "function", "crypto.subtle.exportKey exists");
        assert_equals(typeof cryptoSubtle.wrapKey,     "function", "crypto.subtle.wrapKey exists");
        assert_equals(typeof cryptoSubtle.unwrapKey,   "function", "crypto.subtle.unwrapKey exists");
    }, "crypto interface");
    
    test(function() {
        var zeros = new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        var abv1 = new Uint8Array(8);
        var abv2 = crypto.getRandomValues(abv1);
        assert_equals(abv1, abv2);
        assert_not_equals(base16.stringify(abv2), base16.stringify(zeros));
        var abv3 = new Uint8Array(8);
        var abv4 = crypto.getRandomValues(abv3);
        assert_equals(abv3, abv4);
        assert_not_equals(base16.stringify(abv4), base16.stringify(zeros));
        assert_not_equals(base16.stringify(abv4), base16.stringify(abv2));
    }, "RandomSource");
    
    var SHA = (function() {
        var test1 = async_test("digest SHA-256");
        var test2 = async_test("digest SHA-384");
        
        test1.step(function() {
            // convenient calculator here: http://www.fileformat.info/tool/hash.htm
            var data = base16.parse("6162636462636465636465666465666765666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f7071"),
                result_sha256_hex = "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1";
            var op = cryptoSubtle.digest({ name: "SHA-256" }, data);
            op.onerror = test1.step_func(function() {
                assert_true(false);
                test1.done();
            });
            op.oncomplete = test1.step_func(function(e) {
                assert_equals(base16.stringify(e.target.result), result_sha256_hex);
                test1.done();
            });
        });
        
        test2.step(function() {
            var data = base16.parse("6162636462636465636465666465666765666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f7071"),
                result_sha384_hex = "3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b";
            var op = cryptoSubtle.digest({ name: "SHA-384" }, data);
            op.onerror = test2.step_func(function() {
                assert_true(false);
                test2.done();
            });
            op.oncomplete = test2.step_func(function(e) {
                assert_equals(base16.stringify(e.target.result), result_sha384_hex);
                test2.done();
            });
        })
        
    }());
    
    var AES = (function() {
        
        (function AesImportExportRaw() {
            var keyData = new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                                          0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
                                          0x0E, 0x0F]);
            var test = async_test("importKey/export raw AES-CBC");
            test.step(function() {
                // TODO: Once https://www.w3.org/Bugs/Public/show_bug.cgi?id=21435 is resolved,
                // might need to pass in length as part of AlgorithmIdentifier
                var op = cryptoSubtle.importKey("raw", keyData, { name: "AES-CBC" }, true);
                op.onerror = test.step_func(function (e) {
                    assert_true(false);
                    test.done();
                });
                op.oncomplete = test.step_func(function (e) {
                    var key = e.target.result;
                    assert_not_equals(key, undefined, "crypto exists");
                    assert_true(key.extractable);
                    exportAndCheck(key);
                });
            });
            function exportAndCheck(key) {
                var op = cryptoSubtle.exportKey("raw", key);
                op.onerror = test.step_func(function (e) {
                    assert_true(false);
                    test.done();
                });
                op.oncomplete = test.step_func(function (e) {
                    var keyData2 = e.target.result;
                    assert_not_equals(keyData2, undefined);
                    assert_equals(base16.stringify(keyData2), base16.stringify(keyData));
                    test.done();
                });
            }
        }());
        
        (function AesImportExportJwk() {
            var rawData = base16.parse("17AE37CAD5EC70D2653FBE7E5E42414C"),
                jwkData = latin1.parse(JSON.stringify({
                    alg:    "A128CBC",
                    kty:    "oct",
                    use:    "enc",
                    extractable:    true,
                    k:      base64.stringifyUrlSafe(rawData),
                }));
            var test = async_test("importKey/exportKey jwk A128CBC oct");
            test.step(function() {
                var op = cryptoSubtle.importKey("jwk", jwkData, { name: "AES-CBC" }, true);
                op.onerror = test.step_func(function(e) {
                    assert_true(false);
                    test.done();
                });
                op.oncomplete = test.step_func(function(e) {
                    var key = e.target.result;
                    assert_not_equals(key, undefined);
                    assert_true(key.extractable);
                    assert_array_equals(key.keyUsage, ["encrypt", "decrypt"]);
                    assert_equals(key.type, "secret");
                    exportAndCheck1(key);
                });
            });
            function exportAndCheck1(key) {
                var op = cryptoSubtle.exportKey("raw", key);
                op.onerror = test.step_func(function(e) {
                    assert_true(false);
                    test.done();
                });
                op.oncomplete = test.step_func(function(e) {
                    var rawData2 = e.target.result;
                    assert_not_equals(rawData2, undefined);
                    assert_equals(base16.stringify(rawData2), base16.stringify(rawData));
                    exportAndCheck2(key);
                });
            }
            function exportAndCheck2(key) {
                var op = cryptoSubtle.exportKey("jwk", key);
                op.onerror = test.step_func(function(e) {
                    assert_true(false);
                    test.done();
                });
                op.oncomplete = test.step_func(function(e) {
                    var rawData2 = e.target.result;
                    assert_not_equals(rawData2, undefined);
                    assert_true(objCompare(JSON.parse(latin1.stringify(rawData2)), JSON.parse(latin1.stringify(jwkData))));
                    test.done();
                });
            }
        }());
        
        (function generateKeyAesCbcExtractable() {
            // port it("generateKey AES-CBC (extractable)", function () { to here
        }());

        (function generateKeyAesCbcNotExtractable() {
            // it("generateKey AES-CBC (not extractable)", function () { to here
        }());

        (function encryptDecryptAesCbc() {
            // port it("encrypt/decrypt AES-CBC", function () { to here
        }());
        
    }());
    

    var HMAC = (function() {
        // port describe("HMAC", function () { to here
    }());

    var RSAkeys = (function() {
        // port describe("RSA keys", function () { to here
    }());
    
    // ... rest of describes

    
    /*

    WORK IN PROGRESS
    Porting from Jasmine frameworks to testharness.js framework
    
    // --------------------------------------------------------------------------------

    describe("AES", function () {


        it("generateKey AES-CBC (extractable)", function () {
            var error;

            var keyLength = 128,
                key,
                keyData;

            runs(function () {
                error = undefined;
                var op = cryptoSubtle.generateKey({ name: "AES-CBC", params: { length: keyLength } }, true);
                op.onerror = function (e) {
                    error = "ERROR";
                };
                op.oncomplete = function (e) {
                    key = e.target.result;
                };
            });

            waitsFor(function () {
                return key || error;
            });

            runs(function () {
                expect(error).toBeUndefined();
                expect(key).toBeDefined();
                expect(key.extractable).toBe(true);
            });

            runs(function () {
                error = undefined;
                var op = cryptoSubtle.exportKey("raw", key);
                op.onerror = function (e) {
                    error = "ERROR";
                };
                op.oncomplete = function (e) {
                    keyData = e.target.result;
                };
            });

            waitsFor(function () {
                return keyData || error;
            });

            runs(function () {
                expect(error).toBeUndefined();
                expect(keyData).toBeDefined();
                expect(keyData.length).toEqual(keyLength / 8);
                expect(base16.stringify(keyData)).not.toEqual(base16.stringify([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
            });

        });

        it("generateKey AES-CBC (not extractable)", function () {
            var error;

            var keyLength = 128,
                key,
                keyData;

            runs(function () {
                error = undefined;
                var op = cryptoSubtle.generateKey({ name: "AES-CBC", params: { length: keyLength } }, false);
                op.onerror = function (e) {
                    error = "ERROR";
                };
                op.oncomplete = function (e) {
                    key = e.target.result;
                };
            });

            waitsFor(function () {
                return key || error;
            });

            runs(function () {
                expect(error).toBeUndefined();
                expect(key).toBeDefined();
                expect(key.extractable).toBe(false);
            });

            runs(function () {
                error = undefined;
                var op = cryptoSubtle.exportKey("raw", key);
                op.onerror = function (e) {
                    error = "ERROR";
                };
                op.oncomplete = function (e) {
                    keyData = e.target.result;
                };
            });

            waitsFor(function () {
                return keyData || error;
            });

            runs(function () {
                expect(error).toBeDefined();
                expect(keyData).toBeUndefined();
            });

        });

        it("encrypt/decrypt AES-CBC", function () {

            var error;

            var key,
                keyData = new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F]),
                iv = base16.parse("562e17996d093d28ddb3ba695a2e6f58"),
                clearText_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                clearText = base16.parse(clearText_hex),
                encrypted,
                decrypted;

            runs(function () {
                var op = cryptoSubtle.importKey("raw", keyData, { name: "AES-CBC" }, true, ["encrypt", "decrypt"]);
                op.onerror = function (e) {
                    error = "ERROR";
                };
                op.oncomplete = function (e) {
                    key = e.target.result;
                };
            });

            waitsFor(function () {
                return key || error;
            });

            runs(function () {
                expect(error).toBeUndefined();
                expect(key).toBeDefined();
            });

            runs(function () {
                error = undefined;
                var encryptOp = cryptoSubtle.encrypt({ name: "AES-CBC", params: { iv: iv } }, key, clearText);
                encryptOp.onerror = function (e) {
                    error = "ERROR";
                };
                encryptOp.oncomplete = function (e) {
                    encrypted = e.target.result;
                };
            });

            waitsFor(function () {
                return encrypted || error;
            });

            runs(function () {
                expect(error).toBeUndefined();
                expect(encrypted).toBeDefined();
                expect(base16.stringify(encrypted)).not.toBe(clearText);
            });

            runs(function () {
                error = undefined;
                var decryptOp = cryptoSubtle.decrypt({ name: "AES-CBC", params: { iv: iv } }, key, encrypted);
                decryptOp.onerror = function (e) {
                    error = "ERROR";
                };
                decryptOp.oncomplete = function (e) {
                    decrypted = e.target.result;
                };
            });

            waitsFor(function () {
                return decrypted || error;
            });

            runs(function () {
                expect(error).toBeUndefined();
                expect(decrypted).toBeDefined();
                expect(base16.stringify(decrypted)).toBe(clearText_hex);
            });

        });

    });

    // --------------------------------------------------------------------------------

    describe("HMAC", function () {

        it("generateKey HMAC SHA-256", function () {
            var error;

            var keyLength = 256,   // note: matches the choice of SHA-256
                key,
                keyData;

            runs(function () {
                error = undefined;
                var op = cryptoSubtle.generateKey({ name: "HMAC", params: { hash: {name: "SHA-256"} } }, true);
                op.onerror = function (e) {
                    error = "ERROR";
                };
                op.oncomplete = function (e) {
                    key = e.target.result;
                };
            });

            waitsFor(function () {
                return key || error;
            });

            runs(function () {
                expect(error).toBeUndefined();
                expect(key).toBeDefined();
                expect(key.extractable).toBe(true);
            });

            runs(function () {
                error = undefined;
                var op = cryptoSubtle.exportKey("raw", key);
                op.onerror = function (e) {
                    error = "ERROR";
                };
                op.oncomplete = function (e) {
                    keyData = e.target.result;
                };
            });

            waitsFor(function () {
                return keyData || error;
            });

            runs(function () {
                expect(error).toBeUndefined();
                expect(keyData).toBeDefined();
                expect(keyData.length).toEqual(keyLength / 8);
                expect(base16.stringify(keyData)).not.toBe(base16.stringify([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
            });

        });

        it("importKey/sign/verify HMAC SHA-256", function () {
            var error,
                key,
                keyData = new Uint8Array([
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
                ]);

            runs(function () {
                var op = cryptoSubtle.importKey("raw", keyData, { name: "HMAC", params: { hash: "SHA-256" } }, true, ["sign", "verify"]);
                op.onerror = function (e) {
                    error = "ERROR";
                };
                op.oncomplete = function (e) {
                    key = e.target.result;
                };
            });

            waitsFor(function () {
                return key || error;
            });

            runs(function () {
                expect(error).toBeUndefined();
                expect(key).toBeDefined();
            });

            var data = base16.parse("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
                signature;

            runs(function () {
                error = undefined;
                var signOp = cryptoSubtle.sign({ name: "HMAC", params: { hash: "SHA-256" } }, key, data);
                signOp.onerror = function (e) {
                    error = "ERROR";
                };
                signOp.oncomplete = function (e) {
                    signature = e.target.result;
                };
            });

            waitsFor(function () {
                return signature || error;
            });

            runs(function () {
                expect(error).toBeUndefined();
                expect(signature).toBeDefined();
            });

            var verified;

            runs(function () {
                error = undefined;
                var signOp = cryptoSubtle.verify({ name: "HMAC", params: { hash: "SHA-256" } }, key, signature, data);
                signOp.onerror = function (e) {
                    error = "ERROR";
                };
                signOp.oncomplete = function (e) {
                    verified = e.target.result;
                };
            });

            waitsFor(function () {
                return verified !== undefined || error;
            });

            runs(function () {
                expect(error).toBeUndefined();
                expect(verified).toBe(true);
            });

            // and bad signature

            runs(function () {
                error = undefined;
                verified = undefined;
                data[10] = data[10] ^ 0xFF;
                var signOp = cryptoSubtle.verify({ name: "HMAC", params: { hash: "SHA-256" } }, key, signature, data);
                signOp.onerror = function (e) {
                    error = "ERROR";
                };
                signOp.oncomplete = function (e) {
                    verified = e.target.result;
                };
            });

            waitsFor(function () {
                return verified !== undefined || error;
            });

            runs(function () {
                expect(error).toBeUndefined();
                expect(verified).toBe(false);
            });
        });
    });

    // --------------------------------------------------------------------------------

    describe("RSA keys", function () {

        it("importKey/exportKey jwk RSAES-PKCS1-v1_5 public key", function () {
            var error,
                jwkKeyData,
                rawData2,
                key;

            runs(function () {
                // key data is Uint8Array which is Latin1 encoded "{n: base64, e: base64}" json string
                jwkKeyData = latin1.parse(JSON.stringify({
                    kty: "RSA",
                    alg: "RSA1_5",
                    n: base64.stringifyUrlSafe(base16.parse(
                            "a8b3b284af8eb50b387034a860f146c4919f318763cd6c55" +
                            "98c8ae4811a1e0abc4c7e0b082d693a5e7fced675cf46685" +
                            "12772c0cbc64a742c6c630f533c8cc72f62ae833c40bf258" +
                            "42e984bb78bdbf97c0107d55bdb662f5c4e0fab9845cb514" +
                            "8ef7392dd3aaff93ae1e6b667bb3d4247616d4f5ba10d4cf" +
                            "d226de88d39f16fb"
                    )),
                    e: base64.stringifyUrlSafe(base16.parse("010001")),
                    extractable: true,
                }));
                var op = cryptoSubtle.importKey("jwk", jwkKeyData, { name: "RSAES-PKCS1-v1_5" });
                op.onerror = function (e) {
                    error = "ERROR";
                };
                op.oncomplete = function (e) {
                    key = e.target.result;
                };
            });

            waitsFor(function () {
                return key || error;
            });

            runs(function () {
                expect(error).toBeUndefined();
                expect(key).toBeDefined();
                expect(key.type).toBe("public");

                // TODO: confirm that these checks are valid and add them
                // expect(key.algorithm.name).toBe("RSAES-PKCS1-v1_5");
                // expect(key.extractable).toBe(false);
                // expect(key.keyUsage).toEqual([]);
            });
            
            runs(function () {
                error = undefined;
                rawData2 = undefined;
                var op = cryptoSubtle.exportKey("jwk", key);
                op.onerror = function (e) {
                    error = "ERROR";
                };
                op.oncomplete = function (e) {
                    rawData2 = e.target.result;
                };
            });

            waitsFor(function () {
                return rawData2 || error;
            });

            runs(function () {
                expect(error).toBeUndefined();
                expect(rawData2).toBeDefined();
                expect(JSON.parse(latin1.stringify(rawData2))).toEqual(JSON.parse(latin1.stringify(jwkKeyData)));
            });

        });

        // SPKI - Simple Public Key Infrastructure
        // openssl genrsa -out pair.pem 2048
        // openssl rsa -in pair.pem -out pubkey.der -outform DER -pubout
        // openssl enc -base64 -in pubkey.der
        var spkiPubKeyData = base64.parse(
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsjUf4UZyuZ5JKazU0Kq/" +
            "dbaVY0oQxYZcsCQxRrjKF6yQaHACzeubHHaXRLwXkCVvBf2V0HBdJ/xCiIqwos3X" +
            "CMgMWu0mzlSxfv0kyAuH46SzTZdAt5hJPMSjt+eTJI+9hYq6DNqN09ujBwlhQM2J" +
            "hI9V3tZhBD5nQPTNkXYRD3aZp5wWtErIdXDP4ZXFcPdu6sLjH68WZuR9M6Q5Xztz" +
            "O9DA7+m/7CHDvWWhlvuN15t1a4dwBuxlY0eZh1JjM6OPH9zJ2OKJIVOLNIE2WejQ" +
            "E5a7IarLOHM8bYtBZ7/tSyx3MkN40OjPA7ZWiEpyT/wDiZo45aLlN4vsWJpIcdqS" +
            "RwIDAQAB"
        );

        // PKCS #8: Private Key Information Syntax Standard #8
        // <private key of pair generated above>
        // openssl pkcs8 -topk8 -inform PEM -outform DER -in pair.pem -out privkey.der -nocrypt
        // openssl enc -base64 -in privkey.der
        var pkcs8PrivKeyData = base64.parse(
            "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCyNR/hRnK5nkkp" +
            "rNTQqr91tpVjShDFhlywJDFGuMoXrJBocALN65scdpdEvBeQJW8F/ZXQcF0n/EKI" +
            "irCizdcIyAxa7SbOVLF+/STIC4fjpLNNl0C3mEk8xKO355Mkj72FiroM2o3T26MH" +
            "CWFAzYmEj1Xe1mEEPmdA9M2RdhEPdpmnnBa0Ssh1cM/hlcVw927qwuMfrxZm5H0z" +
            "pDlfO3M70MDv6b/sIcO9ZaGW+43Xm3Vrh3AG7GVjR5mHUmMzo48f3MnY4okhU4s0" +
            "gTZZ6NATlrshqss4czxti0Fnv+1LLHcyQ3jQ6M8DtlaISnJP/AOJmjjlouU3i+xY" +
            "mkhx2pJHAgMBAAECggEAfHDkZicPjdaeOF/b7CqPr99jygW6WHRO3SEo173KQWXb" +
            "IVK2Yp0Xn3SghPrjaWD6ejBuITOVmYpp23cdiVI7yoIHPqdD5ej2WTrkKF0E803b" +
            "d18bbhkFa03VFWK8OVe2fD43VSp4x2wkF5HRO7NLSCnfSNBixtfculs4AU908lov" +
            "lr+aJJYeaUvdvpo5Vk15DVXxO+YiPjVd+oZ/jfZQl3WvOZH9t6STF4Sk4KEntdop" +
            "kFQA6Z3dzcrp5XLMq7twMZMokVfLf0rW+1GX//LKxZhq0UM2HdPliWFvzB5WUbTe" +
            "23cMIanBxONs7alz7J16Pt/nfFTbJpwuyRE9pODLgQKBgQDrSqb1pVMyk9rTIB9E" +
            "ZyaWdyiRHkpzAcYyQGMN/4gLmAlLCQnclTPly7fl33y9uMmHVXd2zoOYSvSLOoNZ" +
            "6mJTHRg59142r92FVpcHz3k5JHjWrLpCTv2lD1NpJTFHwiEv37mbJWgCtfKcN9u1" +
            "gKg9DAKektJoS09pxDqXPqZuFwKBgQDB5E/94gNQ4L7IlY/g3tEBeQu0sbeHMyIe" +
            "MxE6p2HJWCi2akH27nd8AVfUtAnDkrzmcTCRY2CjJH4nM759IhjHlaUzpUeRQb43" +
            "ari8QnXLeE53uVpgDFTtJjH5ytua846H9r4utetr2Y+giAXU3+CdOldfGAJdwajB" +
            "eHigOjdLUQKBgQCR+IRQDTrqO9Qb+ueq9ht4aYBfV110r/sXnd5WBtuN5cqOJJNb" +
            "p6zEuXfjQp0Ozp8oOJuet0vopUfFQI3QsJpDWd93xsFKSByz5h5YmBxqmPfmps3+" +
            "6SZuym1C4/IIxKT2IGPznmdCl0JmLDlABwtYpCTT395tGZuw0C5ROmriDQKBgQCK" +
            "MqmxU/75DrftUG0U4rwmSJjHWkRt4UxYKh4FqHhSgrvCCUqrLp2LjYmE2i57b4Ok" +
            "3Ni5SBQBNGmWl5MWrc7rswXlIdE4/5sM9MxnoxdCx6VmQH7iJugBgE/us2CDuUXG" +
            "M2Cq+o+qd4+f5FQDvu7iIktURFCrcvVNsQiJa/UtgQKBgCGZduyk7mtYatd9M3tG" +
            "HhMA+Q47KB0wbSPhn0YhZc+0VNZkjc5cS9IDn08cEA4HRRfob3Ou0+N9qla3MqXt" +
            "R9C3zb152OL4MmW9/u/0yoPu8NavhX+CbkJ56OeaPsd99a9pEJTRf0+YIkpKA0EZ" +
            "lKXOV21h9WXMBq+z/12CUyy0"
        );

        it("importKey/exportKey spki RSAES-PKCS1-v1_5 public key", function () {
            var error,
                key,
                exportedSpkiKeyData;

            runs(function () {
                error = undefined;
                var op = cryptoSubtle.importKey("spki", spkiPubKeyData, { name: "RSAES-PKCS1-v1_5" }, true);
                op.onerror = function (e) {
                    error = "ERROR";
                };
                op.oncomplete = function (e) {
                    key = e.target.result;
                };
            });

            waitsFor(function () {
                return key || error;
            });

            runs(function () {
                expect(error).toBeUndefined();
                expect(key).toBeDefined();
                expect(key.type).toBe("public");
                expect(key.extractable).toBe(true);
                // TODO: confirm that these checks are valid and add them
                // expect(key.algorithm.name).toBe("RSAES-PKCS1-v1_5");
                // expect(key.keyUsage).toEqual([]);
            });

            // verify exported key matches what was imported
            runs(function () {
                error = undefined;
                var op = cryptoSubtle.exportKey("spki", key);
                op.onerror = function (e) {
                    error = "ERROR";
                };
                op.oncomplete = function (e) {
                    exportedSpkiKeyData = e.target.result;
                };
            });

            waitsFor(function () {
                return error || exportedSpkiKeyData;
            });

            runs(function () {
                expect(error).toBeUndefined();
                expect(exportedSpkiKeyData).toBeDefined();
                expect(base16.stringify(exportedSpkiKeyData)).toBe(base16.stringify(spkiPubKeyData));
            });
        });

        it("importKey/exportKey pkcs8 RSAES-PKCS1-v1_5 private key", function () {
            var error,
                privKey,
                pkcs8PrivKeyData2;

            // import pkcs8-formatted private key
            runs(function () {
                var op = cryptoSubtle.importKey("pkcs8", pkcs8PrivKeyData, { name: "RSAES-PKCS1-v1_5" }, true);
                op.onerror = function (e) {
                    error = "ERROR";
                };
                op.oncomplete = function (e) {
                    privKey = e.target.result;
                };
            });

            waitsFor(function () {
                return privKey || error;
            });

            runs(function () {
                expect(error).toBeUndefined();
                expect(privKey).toBeDefined();
                expect(privKey.type).toBe("private");
                expect(privKey.extractable).toBe(true);
                //expect(privKey.algorithm.name).toBe("RSAES-PKCS1-v1_5");
            });

            // export the private key back out, raw pkcs8 data should be the same
            runs(function () {
                error = undefined;
                var op = cryptoSubtle.exportKey("pkcs8", privKey);
                op.onerror = function (e) {
                    error = "ERROR";
                };
                op.oncomplete = function (e) {
                    pkcs8PrivKeyData2 = e.target.result;
                };
            });

            waitsFor(function () {
                return pkcs8PrivKeyData2 || error;
            });

            runs(function () {
                expect(error).toBeUndefined();
                expect(pkcs8PrivKeyData2).toBeDefined();
                expect(base16.stringify(pkcs8PrivKeyData2)).toBe(base16.stringify(pkcs8PrivKeyData));
            });
        });

        it("importKey RSAES-PKCS1-v1_5 pkcs8 private key + spki public key, encrypt/decrypt", function () {
            var error,
                privKey,
                pubKey;

            // import pkcs8-formatted private key
            runs(function () {
                var op = cryptoSubtle.importKey("pkcs8", pkcs8PrivKeyData, { name: "RSAES-PKCS1-v1_5" }, false);
                op.onerror = function (e) {
                    error = "ERROR";
                };
                op.oncomplete = function (e) {
                    privKey = e.target.result;
                };
            });

            waitsFor(function () {
                return privKey || error;
            });

            runs(function () {
                expect(error).toBeUndefined();
                expect(privKey).toBeDefined();
                expect(privKey.type).toBe("private");
                expect(privKey.extractable).toBe(false);
                //expect(privKey.algorithm.name).toBe("RSAES-PKCS1-v1_5");
            });

            // import corresponding spki-formatted public key
            runs(function () {
                error = undefined;
                var op = cryptoSubtle.importKey("spki", spkiPubKeyData, { name: "RSAES-PKCS1-v1_5" }, false);
                op.onerror = function (e) {
                    error = "ERROR";
                };
                op.oncomplete = function (e) {
                    pubKey = e.target.result;
                };
            });

            waitsFor(function () {
                return pubKey || error;
            });

            runs(function () {
                expect(error).toBeUndefined();
                expect(pubKey).toBeDefined();
                expect(pubKey.type).toBe("public");
                expect(pubKey.extractable).toBe(true);
                // TODO: confirm that these checks are valid and add them
                // expect(pubKey.algorithm.name).toBe("RSAES-PKCS1-v1_5");
            });

            var clearText = base16.parse("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
            var cipherText;

            // encrypt clearText with the public key
            runs(function () {
                error = undefined;
                var encryptOp = cryptoSubtle.encrypt({ name: "RSAES-PKCS1-v1_5" }, pubKey, clearText);
                encryptOp.onerror = function (e) {
                    error = "ERROR";
                };
                encryptOp.oncomplete = function (e) {
                    cipherText = e.target.result;
                };
            });

            waitsFor(function () {
                return cipherText || error;
            });

            runs(function () {
                expect(error).toBeUndefined();
                expect(cipherText).toBeDefined();
                expect(base16.stringify(cipherText)).not.toBe(base16.stringify(clearText));
            });

            var decrypted;

            // decrypt cipherText with the private key, should get the same clearText back
            runs(function () {
                error = undefined;
                var encryptOp = cryptoSubtle.decrypt({ name: "RSAES-PKCS1-v1_5" }, privKey, cipherText);
                encryptOp.onerror = function (e) {
                    error = "ERROR";
                };
                encryptOp.oncomplete = function (e) {
                    decrypted = e.target.result;
                };
            });

            waitsFor(function () {
                return decrypted || error;
            });

            runs(function () {
                expect(error).toBeUndefined();
                expect(decrypted).toBeDefined();
                expect(base16.stringify(decrypted)).toBe(base16.stringify(clearText));
            });
        });

    });

    // --------------------------------------------------------------------------------

    describe("RSA operations", function () {

        var pubKey,
            privKey;

        var initialized;
        beforeEach(function () {
            if (initialized) return;
            initialized = true;

            // generate the keys before each test
            var error;

            runs(function () {
                var genOp = cryptoSubtle.generateKey({ name: "RSASSA-PKCS1-v1_5", params: { modulusLength: 512, publicExponent: new Uint8Array([0x01, 0x00, 0x01]) } }, false);
                genOp.onerror = function (e) {
                    error = "ERROR";
                };
                genOp.oncomplete = function (e) {
                    pubKey = e.target.result.publicKey;
                    privKey = e.target.result.privateKey;
                };
            });

            waitsFor(function () {
                return pubKey || privKey || error;
            });

            runs(function () {
                expect(error).toBeUndefined();
                expect(pubKey).toBeDefined();
                expect(pubKey.extractable).toBeTruthy() // public key is forced extractable
                expect(privKey).toBeDefined();
                expect(privKey.extractable).toBeFalsy(); // private key takes the extractable input arg val
            });
        });

        it("generateKey RSASSA-PKCS1-v1_5", function () {
            // make sure proper keys are created via beforeEach
            runs(function () {
                expect(pubKey).toBeDefined();
                expect(pubKey.type).toBe("public");
                expect(privKey).toBeDefined();
                expect(privKey.type).toBe("private");
                // TODO: confirm that these checks are valid and add them
                // expect(pubKey.algorithm.name).toBe("RSASSA-PKCS1-v1_5");
                // expect(privKey.algorithm.name).toBe("RSASSA-PKCS1-v1_5");
                // TODO: more key tests?
            });
        });

        it("encrypt/decrypt RSAES-PKCS1-v1_5", function () {
            var error,
                clearText = base16.parse("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

            var encrypted;

            // encrypt clearText with the public key
            runs(function () {
                error = undefined;
                var encryptOp = cryptoSubtle.encrypt({ name: "RSAES-PKCS1-v1_5" }, pubKey, clearText);
                encryptOp.onerror = function (e) {
                    error = "ERROR";
                };
                encryptOp.oncomplete = function (e) {
                    encrypted = e.target.result;
                };
            });

            waitsFor(function () {
                return encrypted || error;
            });

            runs(function () {
                expect(error).toBeUndefined();
                expect(encrypted).toBeDefined();
                expect(base16.stringify(encrypted)).not.toBe(base16.stringify(clearText));
            });

            var decrypted;

            // decrypt cipherText with the private key, should get the same clearText back
            runs(function () {
                error = undefined;
                var encryptOp = cryptoSubtle.decrypt({ name: "RSAES-PKCS1-v1_5" }, privKey, encrypted);
                encryptOp.onerror = function (e) {
                    error = "ERROR";
                };
                encryptOp.oncomplete = function (e) {
                    decrypted = e.target.result;
                };
            });

            waitsFor(function () {
                return decrypted || error;
            });

            runs(function () {
                expect(error).toBeUndefined();
                expect(decrypted).toBeDefined();
                expect(base16.stringify(decrypted)).toBe(base16.stringify(clearText));
            });
        });

        it("sign/verify RSASSA-PKCS1-v1_5 SHA-256", function () {
            var error;

            var data = base16.parse("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
            // var data = base64.parse("eyJtZXNzYWdlaWQiOjIwNTQ5MzA2ODcsIm5vbnJlcGxheWFibGUiOmZhbHNlLCJyZW5ld2FibGUiOnRydWUsImNhcGFiaWxpdGllcyI6eyJjb21wcmVzc2lvbmFsZ29zIjpbIkxaVyJdfSwia2V5cmVxdWVzdGRhdGEiOlt7InNjaGVtZSI6IkFTWU1NRVRSSUNfV1JBUFBFRCIsImtleWRhdGEiOnsia2V5cGFpcmlkIjoicnNhS2V5cGFpcklkIiwibWVjaGFuaXNtIjoiUlNBIiwicHVibGlja2V5IjoiVFVsSFNrRnZSMEpCVDFsWFV6WTJObmxIY2s1NVNFZG5OMjB2WjJSbmIwSjFSRmh6SzNCTlNXVkxjVTVQZDJWSmFubHpUWEo0U1U5NFoyeE1TM0ZFTmtsbFdqZHdNVUppVUVWNFdGaEthM05aTkdkVFRrTTNNRU5sUVVKRVVUZEZiM0ZpV0dVd1JEbFVWRTVPTDBwTlVtNUpjbVZ1WlhVNU5XTnhObnBoTUhnMVYxZHphM1pMU0U4emNtRlZPWGRGY0M5WlJWTTNiVlZ6YTJseVdrNUJLMFpVVFZSYU9USmpVMWg2V1M5ck1GRTJaR1UzUVdkTlFrRkJSVDA9In19XX0=");

            var signature;

            // sign data with the private key
            runs(function () {
                error = undefined;
                var signOp = cryptoSubtle.sign({ name: "RSASSA-PKCS1-v1_5", params: { hash: "SHA-256", }, }, privKey, data);
                signOp.onerror = function (e) {
                    error = "ERROR";
                };
                signOp.oncomplete = function (e) {
                    signature = e.target.result;
                };
            });

            waitsFor(function () {
                return signature || error;
            });

            runs(function () {
                expect(error).toBeUndefined();
                // TODO: more tests
                expect(signature).toBeDefined();
            });

            var verified;

            // verify data with the public key
            runs(function () {
                error = undefined;
                var verifyOp = cryptoSubtle.verify({ name: "RSASSA-PKCS1-v1_5", params: { hash: "SHA-256", }, }, pubKey, signature, data);
                verifyOp.onerror = function (e) {
                    error = "ERROR";
                };
                verifyOp.oncomplete = function (e) {
                    verified = e.target.result;
                };
            });

            waitsFor(function () {
                return verified !== undefined || error;
            });

            runs(function () {
                expect(error).toBeUndefined();
                expect(verified).toBe(true);
            });

            // verify data with the public key and bad signature
            runs(function () {
                error = undefined;
                verified = undefined;
                signature[10] = signature[10] ^ 0xFF;
                var verifyOp = cryptoSubtle.verify({ name: "RSASSA-PKCS1-v1_5", params: { hash: "SHA-256", }, }, pubKey, signature, data);
                verifyOp.onerror = function (e) {
                    error = "ERROR";
                };
                verifyOp.oncomplete = function (e) {
                    verified = e.target.result;
                };
            });

            waitsFor(function () {
                return verified !== undefined || error;
            });

            runs(function () {
                expect(error).toBeUndefined();
                expect(verified).toBe(false);
            });

        });

    });

    // --------------------------------------------------------------------------------

    describe("JWK and JWE", function () {

        it("import / export jwk", function () {
            var error;
            var key;
            var exportedData;
            var key128 = new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F]);
            var key256 = new Uint8Array(key128.length * 2);
            key256.set(key128);
            key256.set(key128, key128.length);
            
            // A128CBC import / export
            var jwk1 = latin1.parse(JSON.stringify({
                alg:    "A128CBC",
                kty:    "oct",
                use:    "enc",
                extractable:    true,
                k:      base64.stringifyUrlSafe(key128),
            }));
            runs(function () {
                key = undefined;
                error = undefined;
                var op = cryptoSubtle.importKey("jwk", jwk1, { name: "RSAES-PKCS1-v1_5" }, true);
                op.onerror = function (e) {
                    error = "ERROR";
                };
                op.oncomplete = function (e) {
                    key = e.target.result;
                };
            })
            waitsFor(function () {
                return key || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(key).toBeDefined();
                expect(key.algorithm.name).toBe("AES-CBC");
            });
            runs(function () {
                error = undefined;
                exportedData = undefined;
                var op = cryptoSubtle.exportKey("jwk", key);
                op.onerror = function (e) {
                    error = "ERROR";
                };
                op.oncomplete = function (e) {
                    exportedData = e.target.result;
                };
            })
            waitsFor(function () {
                return exportedData || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(key).toBeDefined();
                expect(JSON.parse(latin1.stringify(exportedData))).toEqual(JSON.parse(latin1.stringify(jwk1)));
            });

            // A256GCM import / export
            var jwk2 = latin1.parse(JSON.stringify({
                alg:    "A256GCM",
                kty:    "oct",
                use:    "enc",
                extractable:    true,
                k:      base64.stringifyUrlSafe(key256),
            }));
            runs(function () {
                key = undefined;
                error = undefined;
                var op = cryptoSubtle.importKey("jwk", jwk2, { name: "RSAES-PKCS1-v1_5" }, true);
                op.onerror = function (e) {
                    error = "ERROR";
                };
                op.oncomplete = function (e) {
                    key = e.target.result;
                };
            })
            waitsFor(function () {
                return key || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(key).toBeDefined();
                expect(key.algorithm.name).toBe("AES-GCM");
            });
            runs(function () {
                error = undefined;
                exportedData = undefined;
                var op = cryptoSubtle.exportKey("jwk", key);
                op.onerror = function (e) {
                    error = "ERROR";
                };
                op.oncomplete = function (e) {
                    exportedData = e.target.result;
                };
            })
            waitsFor(function () {
                return exportedData || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(key).toBeDefined();
                expect(JSON.parse(latin1.stringify(exportedData))).toEqual(JSON.parse(latin1.stringify(jwk2)));
            });

            // HS256 import / export
            var jwk3 = latin1.parse(JSON.stringify({
                alg:    "HS256",
                kty:    "oct",
                use:    "sig",
                extractable:    true,
                k:      base64.stringifyUrlSafe(key256),
            }));
            runs(function () {
                key = undefined;
                error = undefined;
                var op = cryptoSubtle.importKey("jwk", jwk3, { name: "RSAES-PKCS1-v1_5" }, true);
                op.onerror = function (e) {
                    error = "ERROR";
                };
                op.oncomplete = function (e) {
                    key = e.target.result;
                };
            })
            waitsFor(function () {
                return key || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(key).toBeDefined();
                expect(key.algorithm.name).toBe("HMAC");
                expect(key.algorithm.params.hash.name).toBe("SHA-256");
            });
            runs(function () {
                error = undefined;
                exportedData = undefined;
                var op = cryptoSubtle.exportKey("jwk", key);
                op.onerror = function (e) {
                    error = "ERROR";
                };
                op.oncomplete = function (e) {
                    exportedData = e.target.result;
                };
            })
            waitsFor(function () {
                return exportedData || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(key).toBeDefined();
                expect(JSON.parse(latin1.stringify(exportedData))).toEqual(JSON.parse(latin1.stringify(jwk3)));
            });

            // RSA1_5 import / export
            var jwk4 = latin1.parse(JSON.stringify({
                alg:    "RSA1_5",
                kty:    "RSA",
                n:      base64.stringifyUrlSafe(base16.parse(
                            "a8b3b284af8eb50b387034a860f146c4919f318763cd6c55" +
                            "98c8ae4811a1e0abc4c7e0b082d693a5e7fced675cf46685" +
                            "12772c0cbc64a742c6c630f533c8cc72f62ae833c40bf258" +
                            "42e984bb78bdbf97c0107d55bdb662f5c4e0fab9845cb514" +
                            "8ef7392dd3aaff93ae1e6b667bb3d4247616d4f5ba10d4cf" +
                            "d226de88d39f16fb"
                )),
                e:      base64.stringifyUrlSafe(base16.parse("010001")),
                extractable: true,
            }));
            runs(function () {
                key = undefined;
                error = undefined;
                var op = cryptoSubtle.importKey("jwk", jwk4, { name: "AES-CBC" });
                op.onerror = function (e) {
                    error = "ERROR";
                };
                op.oncomplete = function (e) {
                    key = e.target.result;
                };
            })
            waitsFor(function () {
                return key || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(key).toBeDefined();
                expect(key.algorithm.name).toBe("RSAES-PKCS1-v1_5");
            });
            runs(function () {
                error = undefined;
                exportedData = undefined;
                var op = cryptoSubtle.exportKey("jwk", key);
                op.onerror = function (e) {
                    error = "ERROR";
                };
                op.oncomplete = function (e) {
                    exportedData = e.target.result;
                };
            })
            waitsFor(function () {
                return exportedData || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(key).toBeDefined();
                expect(JSON.parse(latin1.stringify(exportedData))).toEqual(JSON.parse(latin1.stringify(jwk4)));
            });

            // A128KW import / export
            var jwk5 = latin1.parse(JSON.stringify({
                alg:    "A128KW",
                kty:    "oct",
                use:    "wrap",
                extractable:    true,
                k:      base64.stringifyUrlSafe(key128),
            }));
            runs(function () {
                key = undefined;
                error = undefined;
                var op = cryptoSubtle.importKey("jwk", jwk5, { name: "RSAES-PKCS1-v1_5" }, true);
                op.onerror = function (e) {
                    error = "ERROR";
                };
                op.oncomplete = function (e) {
                    key = e.target.result;
                };
            })
            waitsFor(function () {
                return key || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(key).toBeDefined();
                expect(key.algorithm.name).toBe("AES-KW");
            });
            runs(function () {
                error = undefined;
                exportedData = undefined;
                var op = cryptoSubtle.exportKey("jwk", key);
                op.onerror = function (e) {
                    error = "ERROR";
                };
                op.oncomplete = function (e) {
                    exportedData = e.target.result;
                };
            })
            waitsFor(function () {
                return exportedData || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(key).toBeDefined();
                expect(JSON.parse(latin1.stringify(exportedData))).toEqual(JSON.parse(latin1.stringify(jwk5)));
            });

            // A256KW import / export
            var jwk6 = latin1.parse(JSON.stringify({
                alg:    "A256KW",
                kty:    "oct",
                use:    "wrap",
                extractable:    true,
                k:      base64.stringifyUrlSafe(key256),
            }));
            runs(function () {
                key = undefined;
                error = undefined;
                var op = cryptoSubtle.importKey("jwk", jwk6, { name: "RSAES-PKCS1-v1_5" }, true);
                op.onerror = function (e) {
                    error = "ERROR";
                };
                op.oncomplete = function (e) {
                    key = e.target.result;
                };
            })
            waitsFor(function () {
                return key || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(key).toBeDefined();
                expect(key.algorithm.name).toBe("AES-KW");
            });
            runs(function () {
                error = undefined;
                exportedData = undefined;
                var op = cryptoSubtle.exportKey("jwk", key);
                op.onerror = function (e) {
                    error = "ERROR";
                };
                op.oncomplete = function (e) {
                    exportedData = e.target.result;
                };
            })
            waitsFor(function () {
                return exportedData || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(key).toBeDefined();
                expect(JSON.parse(latin1.stringify(exportedData))).toEqual(JSON.parse(latin1.stringify(jwk6)));
            });

        });

        it("RSA-OAEP wrapKey / unwrapKey jwe RSA-OAEP A128GCM", function () {
            var error,
                key,
                keyData = new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F]),
                key2,
                keyData2,
                jweData,
                pubKey,
                privKey;

            // generate RSA pub/priv key pair for wrapping with
            runs(function () {
                error = undefined;
                var genOp = cryptoSubtle.generateKey(
                        {
                            name: "RSA-OAEP",
                            params: {
                                modulusLength: 1024,
                                publicExponent: new Uint8Array([0x01, 0x00, 0x01])
                            }
                        },
                        false,
                        ["wrap", "unwrap"]
                );
                genOp.onerror = function (e) {
                    error = "ERROR";
                };
                genOp.oncomplete = function (e) {
                    pubKey  = e.target.result.publicKey;
                    privKey = e.target.result.privateKey;
                };
            });
            waitsFor(function () {
                return (pubKey && privKey) || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(pubKey).toBeDefined();
                expect(privKey).toBeDefined();
            });

            // create the key to be wrapped
            runs(function () {
                error = undefined;
                var op = cryptoSubtle.importKey("raw", keyData, { name: "AES-CBC" }, true);
                op.onerror = function (e) {
                    error = "ERROR";
                };
                op.oncomplete = function (e) {
                    key = e.target.result;
                };
            });
            waitsFor(function () {
                return key || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(key).toBeDefined();
            });

            // wrap the wrap-ee key using the public wrapping key
            runs(function () {
                error = undefined;
                var op = cryptoSubtle.wrapKey(key, pubKey);  // leave out alg as a neg test
                op.onerror = function (e) {
                    error = "ERROR";
                };
                op.oncomplete = function (e) {
                    jweData = e.target.result;
                };
            });
            waitsFor(function () {
                return jweData || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(jweData).toBeDefined();
            });

            // now unwrap the jwe data received from wrapKey, using the private wrapping key
            // this gives us a new key in the key store
            runs(function () {
                error = undefined;
                var op = cryptoSubtle.unwrapKey(jweData, null, privKey, true);
                op.onerror = function (e) {
                    error = "ERROR";
                };
                op.oncomplete = function (e) {
                    key2 = e.target.result;
                };
            });
            waitsFor(function () {
                return key2 || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(key2).toBeDefined();
                expect(key2.algorithm.name).toBe("AES-CBC");
                expect(key2.type).toBe("secret");
            });

            // finally, export this new key and verify the raw key data
            runs(function () {
                error = undefined;
                var op = cryptoSubtle.exportKey("raw", key2);
                op.onerror = function (e) {
                    error = "ERROR";
                };
                op.oncomplete = function (e) {
                    keyData2 = e.target.result;
                };
            });
            waitsFor(function () {
                return keyData2 || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(keyData2).toBeDefined();
                expect(base16.stringify(keyData2)).toEqual(base16.stringify(keyData));
            });
            
            // Wes's "short key" test
            runs(function () {
                error = undefined;
                key2 = undefined;
                // Wes' "short key" test: replace the encrypted CMK with "x"
                var jwe = latin1.stringify(jweData);
                var jweObj = JSON.parse(jwe);
                jweObj.recipients[0].encrypted_key = base64.stringifyUrlSafe([0x78]);
                var newJwe = JSON.stringify(jweObj);
                var op = cryptoSubtle.unwrapKey(latin1.parse(newJwe), null, privKey, true);
                op.onerror = function (e) {
                    error = "ERROR";
                };
                op.oncomplete = function (e) {
                    key2 = e.target.result;
                };
            });
            waitsFor(function () {
                return key2 || error;
            });
            runs(function () {
                expect(error).toBeDefined();
            });
            
            // --- repeat for JWE-CS input

            // now unwrap the jwe data received from wrapKey, using the private wrapping key
            // this gives us a new key in the key store
            runs(function () {
                error = undefined;
                key2 = undefined;
                // Convert from JWE-JS to JWE-CS
                // JWE-JS:
                // { "recipients" : [ { "header" : <header>, "encrypted_key" : <ekey>, "integrity_value" : <integrity> } ],
                //   "initialization_vector" : <initvector>,
                //   "ciphertext" : <ciphertext> }
                // JWE-CS: <header>.<key>.<init>.<ciphertext>.<integrity>
                var jweJson = JSON.parse(latin1.stringify(jweData));
                var jweCs = jweJson.recipients[0].header          + "." +
                            jweJson.recipients[0].encrypted_key   + "." +
                            jweJson.initialization_vector         + "." +
                            jweJson.ciphertext                    + "." +
                            jweJson.recipients[0].integrity_value;
                var op = cryptoSubtle.unwrapKey(latin1.parse(jweCs), null, privKey, true);
                op.onerror = function (e) {
                    error = "ERROR";
                };
                op.oncomplete = function (e) {
                    key2 = e.target.result;
                };
            });
            waitsFor(function () {
                return key2 || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(key2).toBeDefined();
                expect(key2.algorithm.name).toBe("AES-CBC");
                expect(key2.type).toBe("secret");
            });

            // finally, export this new key and verify the raw key data
            runs(function () {
                error = undefined;
                keyData2 = undefined;
                var op = cryptoSubtle.exportKey("raw", key2);
                op.onerror = function (e) {
                    error = "ERROR";
                };
                op.oncomplete = function (e) {
                    keyData2 = e.target.result;
                };
            });
            waitsFor(function () {
                return keyData2 || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(keyData2).toBeDefined();
                expect(base16.stringify(keyData2)).toEqual(base16.stringify(keyData));
            });

            // --- repeat for JWE-JS input, with multiple recipients

            runs(function () {
                error = undefined;
                key2 = undefined;
                // Add multiple recipients to the JWE-JS, only one of which will succeed
                // JWE-JS:
                // { "recipients" : [ {"header" : <header>, "encrypted_key" : <ekey>, "integrity_value" : <integrity>}, ... ],
                //   "initialization_vector" : <initvector>,
                //   "ciphertext" : <ciphertext> }
                var jweJson = JSON.parse(latin1.stringify(jweData));
                var goodRecipient = JSON.parse(JSON.stringify(jweJson.recipients[0])); // poor-man's object clone
                var badRecipient = JSON.parse(JSON.stringify(goodRecipient)); // poor-man's object clone
                badRecipient.encrypted_key = badRecipient.encrypted_key.substr(0, 2) + "x" + badRecipient.encrypted_key.substr(2+1); // corrupt the CMK for the bad one
                // overwrite the recipients array; recipient with the non-corrupt key is third
                jweJson.recipients = [badRecipient, badRecipient, goodRecipient, badRecipient];
                var op = cryptoSubtle.unwrapKey(latin1.parse(JSON.stringify(jweJson)), null, privKey, true);
                op.onerror = function (e) {
                    error = "ERROR";
                };
                op.oncomplete = function (e) {
                    key2 = e.target.result;
                };
            });
            waitsFor(function () {
                return key2 || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(key2).toBeDefined();
                expect(key2.algorithm.name).toBe("AES-CBC");
                expect(key2.type).toBe("secret");
            });

            // finally, export this new key and verify the raw key data
            runs(function () {
                error = undefined;
                keyData2 = undefined;
                var op = cryptoSubtle.exportKey("raw", key2);
                op.onerror = function (e) {
                    error = "ERROR";
                };
                op.oncomplete = function (e) {
                    keyData2 = e.target.result;
                };
            });
            waitsFor(function () {
                return keyData2 || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(keyData2).toBeDefined();
                expect(base16.stringify(keyData2)).toEqual(base16.stringify(keyData));
            });

        });
        
        it("AES-KW wrapKey / unwrapKey jwe A128KW A128GCM", function () {
            var error,
                wrapeeKey,
                wrapeeKeyData,
                wrapporKey,
                wrappedKeyJwe,
                unwrappedWrappeeKey,
                unwrappedWrappeeKeyData;
            
            // generate a key to be wrapped
            runs(function () {
                error = undefined;
                var op = cryptoSubtle.generateKey({ name: "HMAC", params: { hash: {name: "SHA-256"} } }, true);
                op.onerror = function (e) {
                    error = "ERROR";
                };
                op.oncomplete = function (e) {
                    wrapeeKey = e.target.result;
                };
            });
            waitsFor(function () {
                return wrapeeKey || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(wrapeeKey).toBeDefined();
            });
            
            // export the wrap-ee key data for later checking
            runs(function () {
                error = undefined;
                var op = cryptoSubtle.exportKey("raw", wrapeeKey);
                op.onerror = function (e) {
                    error = "ERROR";
                };
                op.oncomplete = function (e) {
                    wrapeeKeyData = e.target.result;
                };
            });
            waitsFor(function () {
                return wrapeeKeyData || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(wrapeeKeyData).toBeDefined();
            });
            
            // generate a wrapping key
            runs(function () {
                error = undefined;
                var op = cryptoSubtle.generateKey({ name: "AES-KW", params: { length: 128 } });
                op.onerror = function (e) {
                    error = "ERROR";
                };
                op.oncomplete = function (e) {
                    wrapporKey = e.target.result;
                };
            });
            waitsFor(function () {
                return wrapporKey || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(wrapporKey).toBeDefined();
            });
            
            // wrap the wrap-ee using the wrap-or
            runs(function () {
                error = undefined;
                var op = cryptoSubtle.wrapKey(wrapeeKey, wrapporKey, { name: "AES-KW" });
                op.onerror = function (e) {
                    error = "ERROR";
                };
                op.oncomplete = function (e) {
                    wrappedKeyJwe = e.target.result;
                };
            });
            waitsFor(function () {
                return wrappedKeyJwe || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(wrappedKeyJwe).toBeDefined();
            });
            
            // unwrap the resulting JWE
            runs(function () {
                error = undefined;
                var op = cryptoSubtle.unwrapKey(wrappedKeyJwe, null, wrapporKey, true);
                op.onerror = function (e) {
                    error = "ERROR";
                };
                op.oncomplete = function (e) {
                    unwrappedWrappeeKey = e.target.result;
                };
            });
            waitsFor(function () {
                return unwrappedWrappeeKey || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(unwrappedWrappeeKey).toBeDefined();
                expect(unwrappedWrappeeKey.algorithm.name).toBe("HMAC");
            });
            
            // export the raw key and compare to the original
            runs(function () {
                error = undefined;
                var op = cryptoSubtle.exportKey("raw", unwrappedWrappeeKey);
                op.onerror = function (e) {
                    error = "ERROR";
                };
                op.oncomplete = function (e) {
                    unwrappedWrappeeKeyData = e.target.result;
                };
            });
            waitsFor(function () {
                return unwrappedWrappeeKeyData || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(unwrappedWrappeeKeyData).toBeDefined();
                expect(base16.stringify(unwrappedWrappeeKeyData)).toEqual(base16.stringify(wrapeeKeyData));
            });
            
        });

        it("unwrapKey jwe (RSA-OAEP + A128GCM) + jwk", function () {

            var error,
                unwrappedKey,
                wrappingKeyPrivate,
                rawKeyData;

            // import a specific private RSA key to unwrap a known JWE with
            runs(function () {
                error = undefined;
                // This unwrapping key is taken from a run of Wes's java test code.
                // If is required to unwrap the test data from the same run used
                // in the unwrap test below.
                var pkcs8PrivKeyData = base64.parse(
                    "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAMeERCGt3nccSlob" +
                    "LMadbUX5q165j5Ds0832Al4/had/a9PiUpsW0MarYBhPd4j0amIC8zU0PZSr5khi" +
                    "w3WSF/+sV+N8COh8h8ClBQ3hxLTX/Mmnp5ioz5FBLEKWmHykNat042Ml7Rt9Opfg" +
                    "ESC63/KxGjAM1BzgxMmEUS8pxbYnAgMBAAECgYEAwIIzxxdflygZ6bVcz8toe2M6" +
                    "4ixDhT+t4oXjpRK/oG1HGmu+7tvl2DvVfb93hBLpbuaPyp88Z+4xRVjeZdvwAFGo" +
                    "PWUOgWPB3soi2q7BrDev1svZ499YnbhnxhAdXyLowuG3cituy6pydYnpDUn246qG" +
                    "YkhsrnNumb1n0bZ92DkCQQD1eefu1upV4T+V8my443Mcf6VJfmkkGYLgMboFmBo4" +
                    "nmE7yEe1gZp5AK2zwLBroDAcBtc6EXUahrQ3+c9rzIj7AkEA0BH0pdipyRZFGBX/" +
                    "n1OH4q9kjWDnnS16uMYrcAu8MTSbcaolOHWMMXE0I8ce2xqjSV3NPExLBnlc814Y" +
                    "BglXxQJBAM4NumZ9+M6F+T4A9MpuAl5Vt4Ttm4w17eoLU78GYlxMdgocoDT3yZbw" +
                    "vt44TN7K5Bdilp+jr8zIbdbe1wIB+qkCQEeVVdjU8JzI955wuxACeeaINwzYwPZ3" +
                    "VhhJvVn//4/iLHRvd/yznDbKXojMkZYJ1RGBnwFWsh0ZFdx4i8VP440CQBukT0WS" +
                    "CgcdYiD2HQl/3x0Jjx7W9jbJqFrOVjufV5pdgC3ZoztvklDGkl32iB33lBIPnKkj" +
                    "vxzYXFLCSXTjN/4="
                );
                var op = cryptoSubtle.importKey("pkcs8", pkcs8PrivKeyData, { name: "RSA-OAEP", params: { hash: { name: "SHA-1"} } }, false);
                op.onerror = function (e) {
                    error = "ERROR";
                };
                op.oncomplete = function (e) {
                    wrappingKeyPrivate = e.target.result;
                };
            });
            waitsFor(function () {
                return wrappingKeyPrivate || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(wrappingKeyPrivate).toBeDefined();
                expect(wrappingKeyPrivate.type).toBe("private");
                expect(wrappingKeyPrivate.extractable).toBe(false);
                expect(wrappingKeyPrivate.algorithm.name).toBe("RSA-OAEP");
            });

            // unwrap a specific JWE that was wrapped with the public version of
            // the private wrapping key above
            runs(function () {
                error = undefined;
                // jweKeyData is a JWE Compact Serialization: A representation of the JWE as the concatenation of:
                //     Encoded JWE Header,
                //     Encoded JWE Encrypted Content Master Key (CMK),
                //     Encoded JWE Initialization Vector,
                //     Encoded JWE Ciphertext,
                //     Encoded JWE Integrity Value,
                // in that order, with the five strings being separated by four period ('.') characters.
                // Encoding of each part is latin1 url-safe base64 encoding
                // This particular JWE data is RSA-OAEP + A128GCM
                // The cleartext wrapped inside it is a JWK with the value
                // {"alg":"A128","kty":"oct","use":"enc","extractable":false,"k":"F643ytXscNJlP75-XkJBTA"}

                // NOTE:
                // This data is not JWK compliant. The native code was hacked to accept JWK alg 'A128'
                // so we can use this known data in this test.

                var jweKeyData =latin1.parse(
                    "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExMjhHQ00ifQ" + "." +
                    "rxekf14ceqA0M9pBM7lavZ9fbSKhDw-LFrZ2jZg2E4BbOhhc69QJvDP56AcCAjhpY8ECm0SAsBFsPF7LduZnEfK1DyfeS09U1TVrQiRvN97eWtNZ26ja8dxXNETPV14VDgf9ODUa8ecZvEI7hroAV9ZG8UJWaYuxy_pPLLVu7mg" + "." +
                    "6cZml7DurDVOuGWD37xQ-g" + "." +
                    "Be5kJUkz9FpZdg0wTKozGcDXzGcBFbIu9vk4HXGhRTKtLl8Zej_l9wHUfNHvT62cfZrJQKh8OlqJrGoBa5LoOs56HHXSS4GLiV3m_dOODP3uLQkDAH-D" + "." +
                    "P4HvqHNjx3sKu4uFPqZHcw");

                var unwrapOp = cryptoSubtle.unwrapKey(jweKeyData, null, wrappingKeyPrivate);

                unwrapOp.onerror = function (e) {
                    error = "ERROR";
                };
                unwrapOp.oncomplete = function (e) {
                    unwrappedKey = e.target.result;
                };
            });
            waitsFor(function () {
                return unwrappedKey || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(unwrappedKey).toBeDefined();
                expect(unwrappedKey.algorithm).toEqual({"name":"AES-CBC"});
                expect(unwrappedKey.extractable).toBe(false);
                expect(base16.stringify(unwrappedKey.keyUsage)).toBe(base16.stringify(["encrypt","decrypt"]));
                expect(unwrappedKey.type).toBe("secret");
            });

        });

        it("generateKey(RSA)/importKey(AES)/encrypt/wrapKey/unwrapKey/decrypt", function () {
            var error,
                pubKey,
                privKey,

                encryptionKeyData = new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F]),
                encryptionKey,
                wrappedKeyData,
                unwrappedEncryptionKey,

                data = base16.parse("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
                iv = base16.parse("562e17996d093d28ddb3ba695a2e6f58"),
                encryptedData,
                decryptedData;

            // generate RSA pub/priv key pair for wrapping
            runs(function () {
                error = undefined;
                var genOp = cryptoSubtle.generateKey(
                        {
                            name: "RSA-OAEP",
                            params: {
                                modulusLength: 1024,
                                publicExponent: new Uint8Array([0x01, 0x00, 0x01])
                            }
                        },
                        false,
                        ["wrap", "unwrap"]
                );
                genOp.onerror = function (e) {
                    error = "ERROR";
                };
                genOp.oncomplete = function (e) {
                    pubKey = e.target.result.publicKey;
                    privKey = e.target.result.privateKey;
                };
            });
            waitsFor(function () {
                return (pubKey && privKey) || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(pubKey).toBeDefined();
                expect(privKey).toBeDefined();
            });

            // import an AES encryptionKey
            runs(function () {
                error = undefined;
                var op = cryptoSubtle.importKey("raw", encryptionKeyData, { name: "AES-CBC" }, true, ["encrypt", "decrypt"]);
                op.onerror = function (e) {
                    error = "ERROR";
                };
                op.oncomplete = function (e) {
                    encryptionKey = e.target.result;
                };
            });
            waitsFor(function () {
                return encryptionKey || error;
            });

            runs(function () {
                expect(error).toBeUndefined();
                expect(encryptionKey).toBeDefined();
            });

            // encrypt data with the encryptionKey
            runs(function () {
                error = undefined;
                var encryptOp = cryptoSubtle.encrypt({ name: "AES-CBC", params: { iv: iv } }, encryptionKey, data);
                encryptOp.onerror = function (e) {
                    error = "ERROR";
                };
                encryptOp.oncomplete = function (e) {
                    encryptedData = e.target.result;
                };
            });
            waitsFor(function () {
                return encryptedData || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(encryptedData).toBeDefined();
                expect(base16.stringify(encryptedData)).not.toBe(base16.stringify(data));
            });

            // wrap the encryptionKey with pubKey to get a JCS/JWE wrappedKey
            runs(function () {
                error = undefined;
                var op = cryptoSubtle.wrapKey(encryptionKey, pubKey, { name: "RSA-OAEP" });
                op.onerror = function (e) {
                    error = "ERROR";
                };
                op.oncomplete = function (e) {
                    wrappedKeyData = e.target.result;
                };
            });
            waitsFor(function () {
                return wrappedKeyData || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(wrappedKeyData).toBeDefined();
            });

            // unwrap wrappedKeyData using priKey to get a new key that will be
            // equivalent to the encryptionKey that was wrapped
            runs(function () {
                error = undefined;
                var unwrapOp = cryptoSubtle.unwrapKey(wrappedKeyData, null, privKey);
                unwrapOp.onerror = function (e) {
                    error = "ERROR";
                };
                unwrapOp.oncomplete = function (e) {
                    unwrappedEncryptionKey = e.target.result;
                };
            });
            waitsFor(function () {
                return unwrappedEncryptionKey || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(unwrappedEncryptionKey).toBeDefined();
            });

            // decrypt the data with unwrappedEncryptionKey
            runs(function () {
                error = undefined;
                var decryptOp = cryptoSubtle.decrypt({ name: "AES-CBC", params: { iv: iv } }, unwrappedEncryptionKey, encryptedData);
                decryptOp.onerror = function (e) {
                    error = "ERROR";
                };
                decryptOp.oncomplete = function (e) {
                    decryptedData = e.target.result;
                };
            });
            waitsFor(function () {
                return decryptedData || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(decryptedData).toBeDefined();
                expect(base16.stringify(decryptedData)).toBe(base16.stringify(data));
            });

        });

    });

    // --------------------------------------------------------------------------------

    describe("Diffie-Hellman", function () {
        
        it("generateKey / deriveKey", function () {
            var error,
                pubKey1,
                privKey1,
                pubKey2,
                privKey2,
                pubKey2Data,
                sharedKey,
                sharedKeyData,
                prime = base64.parse(
                    "lpTp2Nk6WsdMUJtLvOhekhMs0ZzOR30afkfVJ9nsKRUV8Liz4ertUAbh" +
                    "sbkeoluRoBsQ4ug0uNZgsuMhrWRM4ag7Mo2QFO5+FvHkT/6JV5rD7kfW" +
                    "aLa3ZofC/pCjW15gKP0E7+qII3Ps9gui9jfkzaobYInWwLVhqOUg55beJ98="),
                generator = base64.parse("AAU=");
            
            // generate the local key pair
            runs(function () {
                error = undefined;
                var op = cryptoSubtle.generateKey(
                    {
                        name: "DH",
                        params: {
                            prime: prime,
                            generator: generator,
                        }
                    },
                    false,
                    ["encrypt", "decrypt"]
                );
                op.onerror = function (e) {
                    error = "ERROR";
                };
                op.oncomplete = function (e) {
                    pubKey1  = e.target.result.publicKey;
                    privKey1 = e.target.result.privateKey;
                };
            });
            waitsFor(function () {
                return pubKey1 || privKey1 || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(pubKey1).toBeDefined();
                expect(pubKey1.extractable).toBeTruthy() // public key is forced extractable
                expect(privKey1).toBeDefined();
                expect(privKey1.extractable).toBeFalsy(); // private key takes the extractable input arg val
            });
            
            // generate the remote key pair
            runs(function () {
                error = undefined;
                var op = cryptoSubtle.generateKey(
                    {
                        name: "DH",
                        params: {
                            prime: prime,
                            generator: generator,
                        }
                    },
                    false,
                    ["encrypt", "decrypt"]
                );
                op.onerror = function (e) {
                    error = "ERROR";
                };
                op.oncomplete = function (e) {
                    pubKey2  = e.target.result.publicKey;
                    privKey2 = e.target.result.privateKey;
                };
            });
            waitsFor(function () {
                return pubKey2 || privKey2 || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(pubKey2).toBeDefined();
                expect(pubKey2.extractable).toBeTruthy() // public key is forced extractable
                expect(privKey2).toBeDefined();
                expect(privKey2.extractable).toBeFalsy(); // private key takes the extractable input arg val
            });
            
            // extract the remote public key
            runs(function () {
                error = undefined;
                var op = cryptoSubtle.exportKey("raw", pubKey2);
                op.onerror = function (e) {
                    error = "ERROR";
                };
                op.oncomplete = function (e) {
                    pubKey2Data = e.target.result;
                };
            });
            waitsFor(function () {
                return pubKey2Data || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(pubKey2Data).toBeDefined();
            });
            
            // derive a shared key using the local public key and the extracted
            // remote public key data
            runs(function () {
                error = undefined;
                var op = cryptoSubtle.deriveKey(
                    {
                        name: "DH",
                        params: { "public": pubKey2Data }
                    },
                    pubKey1,
                    { name:  "AES-CBC" },
                    true,
                    ["encrypt", "decrypt"]);
                op.onerror = function (e) {
                    error = "ERROR";
                };
                op.oncomplete = function (e) {
                    sharedKey  = e.target.result;
                };
            });
            waitsFor(function () {
                return sharedKey || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(sharedKey).toBeDefined();
                expect(sharedKey.extractable).toBe(true);
                expect(sharedKey.keyUsage).toEqual(["encrypt", "decrypt"]);
                expect(sharedKey.type).toBe("secret");
                expect(sharedKey.algorithm.name).toBe("AES-CBC");
            });
           
            // extract the derived key
            runs(function () {
                error = undefined;
                var op = cryptoSubtle.exportKey("raw", sharedKey);
                op.onerror = function (e) {
                    error = "ERROR";
                };
                op.oncomplete = function (e) {
                    sharedKeyData = e.target.result;
                };
            });
            waitsFor(function () {
                return sharedKeyData || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(sharedKeyData).toBeDefined();
            });
            
        });
    });

    // --------------------------------------------------------------------------------

    xdescribe("local-storage", function () {

        it("exportKey/importKey local-storage AES-CBC", function () {

            var error;

            // create an AES key
            var keyData = new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F]),
                key;

            runs(function () {
                var op = cryptoSubtle.importKey("raw", keyData, { name: "AES-CBC" }, false, ["encrypt", "decrypt"]);
                op.onerror = function (e) {
                    error = "ERROR";
                };
                op.oncomplete = function (e) {
                    key = e.target.result;
                };
            });

            waitsFor(function () {
                return key || error;
            });

            runs(function () {
                expect(error).toBeUndefined();
                expect(key).toBeDefined();
                expect(key.extractable).toBe(false);
            });

            // export it

            var exportedKeyData;

            runs(function () {
                var op = cryptoSubtle.exportKey("local-storage", key);
                op.onerror = function (e) {
                    error = "ERROR";
                };
                op.oncomplete = function (e) {
                    exportedKeyData = e.target.result;
                };
            });

            waitsFor(function () {
                return exportedKeyData || error;
            });

            runs(function () {
                expect(error).toBeUndefined();
                expect(exportedKeyData).toBeDefined();
                // TODO: sanity check of exportedKeyData
            });

            // import it back

            var importedKey;

            runs(function () {
                var op = cryptoSubtle.importKey("local-storage", exportedKeyData);
                op.onerror = function (e) {
                    error = "ERROR";
                };
                op.oncomplete = function (e) {
                    importedKey = e.target.result;
                };
            });

            waitsFor(function () {
                return importedKey || error;
            });

            runs(function () {
                expect(error).toBeUndefined();
                expect(importedKey).toBeDefined();
                // TODO: compare importedKey == key
            });

        });

        it("exportKey/importKey local-storage AES-CBC (negative test with tampered data)", function () {

            var error;

            // create an AES key
            var keyData = new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F]),
                key;

            runs(function () {
                var op = cryptoSubtle.importKey("raw", keyData, { name: "AES-CBC" }, false, ["encrypt", "decrypt"]);
                op.onerror = function (e) {
                    error = "ERROR";
                };
                op.oncomplete = function (e) {
                    key = e.target.result;
                };
            });

            waitsFor(function () {
                return key || error;
            });

            runs(function () {
                expect(error).toBeUndefined();
                expect(key).toBeDefined();
                expect(key.extractable).toBe(false);
            });

            // export it

            var exportedKeyData;

            runs(function () {
                var op = cryptoSubtle.exportKey("local-storage", key);
                op.onerror = function (e) {
                    error = "ERROR";
                };
                op.oncomplete = function (e) {
                    exportedKeyData = e.target.result;
                };
            });

            waitsFor(function () {
                return exportedKeyData || error;
            });

            runs(function () {
                expect(error).toBeUndefined();
                expect(exportedKeyData).toBeDefined();
                // TODO: sanity check of exportedKeyData
            });

            // import it back

            var importedKey;

            runs(function () {
                error = undefined;

                exportedKeyData[10] = exportedKeyData[10] ^ 0xFF;

                var op = cryptoSubtle.importKey("local-storage", exportedKeyData);
                op.onerror = function (e) {
                    error = "ERROR";
                };
                op.oncomplete = function (e) {
                    importedKey = e.target.result;
                };
            });

            waitsFor(function () {
                return importedKey || error;
            });

            runs(function () {
                expect(error).toBeDefined();
                expect(importedKey).toBeUndefined();
            });

        });

        it("exportKey/importKey local-storage HMAC SHA-256", function () {

            var error;

            // create an AES key
            var keyData = new Uint8Array([
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
                ]),
                key;

            runs(function () {
                var op = importKey("raw", keyData, { name: "HMAC", params: { hash: "SHA-256" } }, false, ["sign", "verify"]);
                op.onerror = function (e) {
                    error = "ERROR";
                };
                op.oncomplete = function (e) {
                    key = e.target.result;
                };
            });

            waitsFor(function () {
                return key || error;
            });

            runs(function () {
                expect(error).toBeUndefined();
                expect(key).toBeDefined();
                expect(key.extractable).toBe(false);
            });

            // export it

            var exportedKeyData;

            runs(function () {
                var op = cryptoSubtle.exportKey("local-storage", key);
                op.onerror = function (e) {
                    error = "ERROR";
                };
                op.oncomplete = function (e) {
                    exportedKeyData = e.target.result;
                };
            });


            waitsFor(function () {
                return exportedKeyData || error;
            });

            runs(function () {
                expect(error).toBeUndefined();
                expect(exportedKeyData).toBeDefined();
                // TODO: sanity check of exportedKeyData
            });

            // import it back

            var importedKey;

            runs(function () {
                var op = cryptoSubtle.importKey("local-storage", exportedKeyData);
                op.onerror = function (e) {
                    error = "ERROR";
                };
                op.oncomplete = function (e) {
                    importedKey = e.target.result;
                };
            });

            waitsFor(function () {
                return importedKey || error;
            });

            runs(function () {
                expect(error).toBeUndefined();
                expect(importedKey).toBeDefined();
                // TODO: compare importedKey == key
            });

        });

    });
*/
})();
