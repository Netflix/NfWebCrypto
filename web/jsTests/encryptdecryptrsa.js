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

describe("EncryptDecryptRSA", function () {

	var PUBKEY, PRIVKEY;

	beforeEach(function () {
		//Different modulus,publicExponent used than sign-verify rsa
		// equivalent to 257 
		//www.rsa.com/rsalabs/node.asp?id=2148
		var fermatF4 = new Uint8Array([0x00, 0x01]);
		var error;
		runs(function () {
			var genOp = nfCrypto.generateKey({
				name: "RSASSA-PKCS1-v1_5",
				params: {
					//2048 bit RSA key can encrypt (n/8) - 11 bytes for PKCS
					//With given 2048 bit key it can encrypt 245 bytes
					modulusLength: 2048,
					publicExponent: fermatF4,
				},
			});
			genOp.onerror = function (e) {
				error = "ERROR :: " + e.target.result;
			};
			genOp.oncomplete = function (e) {
				PUBKEY = e.target.result.publicKey;
				PRIVKEY = e.target.result.privateKey;
			};
		});

		waitsFor(function () {
			return PUBKEY || PRIVKEY || error;
		});

		runs(function () {
			expect(error).toBeUndefined();
			//Doing checks on keys to validate Public Key structure
			expect(PUBKEY.algorithm).toEqual("RSASSA-PKCS1-v1_5");
			expect(PUBKEY.extractable).toBeFalsy();
			expect(PUBKEY.keyUsages.length).toEqual(0);
			//TODO: Re-enable this check when we know what default values should be
			//expect(PUBKEY.keyUsages[0]).toEqual("verify");
			expect(PUBKEY.keyUsages).not.toBeNull();
			expect(PUBKEY.type).toEqual("public");
			//Handle is how C++ correlates keys with JS
			//0 implies invalid key
			expect(PUBKEY.handle).not.toEqual(0);

			//Doing checks on keys to validate Private Key structure
			expect(PRIVKEY.algorithm).toEqual("RSASSA-PKCS1-v1_5");
			expect(PRIVKEY.extractable).toBeFalsy();
			expect(PRIVKEY.keyUsages.length).toEqual(0);
			//TODO: Re-enable this check when we know what default values should be
			//expect(PRIVKEY.keyUsages[0]).toEqual("sign");
			expect(PRIVKEY.type).toEqual("private");
			expect(PRIVKEY.handle).not.toEqual(0);
			expect(PRIVKEY.handle).not.toEqual(PUBKEY.handle);
		});
	});

	afterEach(function () {
		PUBKEY = undefined;
		PRIVKEY = undefined;
	});

	it("RsaEncryptDecryptHappyPath", function () {
		var error = undefined;
		var clearText = hex2abv("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
		var encrypted = undefined;
		var decrypted = undefined;

		runs(function () {
			// encrypt clearText with the public key
			var encryptOp = nfCrypto.encrypt("RSAES-PKCS1-v1_5", PUBKEY, clearText);
			encryptOp.onerror = function (e) {
				error = "ERROR :: " + e.target.result;
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
			expect(encrypted).not.toBeNull();
			expect(encrypted).not.toBe(clearText);
		});

		runs(function () {
			error = undefined;
			var encryptOp = nfCrypto.decrypt("RSAES-PKCS1-v1_5", PRIVKEY, encrypted);
			encryptOp.onerror = function (e) {
				error = "ERROR :: " + e.target.result;
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
			expect(decrypted).toEqual(clearText);
		});
	});
	
	//Large data > 245 bytes, so expected to fail
	it("RsaEncryptDecryptLargeData", function () {
		var error = undefined;
		var clearText_notHex = "eyJtZXNzYWdlaWQiOjQ2MDQwODM3Niwibm9ucmVwbGF5YWJsZSI6ZmFsc2UsInJlbmV3YWJsZSI6dHJ1ZSwiY2FwYWJpbGl0aWVzIjp7ImNvbXByZXNzaW9uYWxnb3MiOlsiTFpXIl19LCJrZXlyZXF1ZXN0ZGF0YSI6W3sic2NoZW1lIjoiQVNZTU1FVFJJQ19XUkFQUEVEIiwia2V5ZGF0YSI6eyJrZXlwYWlyaWQiOiJyc2FLZXlwYWlySWQiLCJtZWNoYW5pc20iOiJSU0EiLCJwdWJsaWNrZXkiOiJUVWxIU2tGdlIwSkJUMWxYVXpZMk5ubEhjazU1U0Vkbk4yMHZaMlJuYjBKMVJGaHpLM0JOU1dWTGNVNVBkMlZKYW5selRYSjRTVTk0WjJ4TVMzRkVOa2xsV2pkd01VSmlVRVY0V0ZoS2EzTlpOR2RUVGtNM01FTmxRVUpFVVRkRmIzRmlXR1V3UkRsVVZFNU9MMHBOVW01SmNtVnVaWFU1TldOeE5ucGhNSGcxVjFkemEzWkxTRTh6Y21GVk9YZEZjQzlaUlZNM2JWVnphMmx5V2s1QkswWlVUVlJhT1RKalUxaDZXUzlyTUZFMlpHVTNRV2ROUWtGQlJUMD0ifX1dfQ==";
		//Converting from base64 to abv
		var clearText = base64.parse(clearText_notHex);
		var encrypted = undefined;
		var decrypted = undefined;

		runs(function () {
			error = undefined;
			var encryptOp = nfCrypto.encrypt("RSAES-PKCS1-v1_5", PUBKEY, clearText);
			encryptOp.onerror = function (e) {
				error = "ERROR :: " + e.target.result;
			};
			encryptOp.oncomplete = function (e) {
				encrypted = e.target.result;
			};
		});

		waitsFor(function () {
			return encrypted || error;
		});

		runs(function () {
			expect(error).toBeDefined("ERROR: digest too large");
			expect(encrypted).toBeUndefined();
		});

	});//it("RsaEncryptDecryptLargeData")
	
	it("EncryptionDecryptionMisMatch", function () {
		var error = undefined;
		var clearText = hex2abv("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
		var encrypted = undefined;
		var decrypted = undefined;

		runs(function () {
			var encryptOp = nfCrypto.encrypt("RSAES-PKCS1-v1_5", PUBKEY, clearText);
			encryptOp.onerror = function (e) {
				error = "ERROR: " + e.target.result;
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
			expect(encrypted).not.toBeNull();
			expect(encrypted).not.toBe(clearText);
		});

		runs(function () {
			//Manipulating encrypted data
			encrypted[0] = encrypted[0] + 1;
			var encryptOp = nfCrypto.decrypt("RSAES-PKCS1-v1_5", PRIVKEY, encrypted);
			encryptOp.onerror = function (e) {
				error = "ERROR: " + e.target.result;
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
			expect(decrypted).not.toEqual(clearText);
		});
	});//it("EncryptionDecryptionMisMatch")
	
	it("RsaEncryptNullData", function () {
		var error = undefined;
		var clearText = null;
		var encrypted = undefined;
		var decrypted = undefined;

		runs(function () {
			var encryptOp = nfCrypto.encrypt("RSAES-PKCS1-v1_5", PUBKEY, clearText);
			encryptOp.onerror = function (e) {
				error = "ERROR: " + e.target.result;
			};
			encryptOp.oncomplete = function (e) {
				encrypted = e.target.result;
			};
		});

		waitsFor(function () {
			return encrypted || error;
		});

		runs(function () {
			expect(error).toBe("ERROR: bad or missing parameter");
			expect(encrypted).toBeUndefined();
		});
	});//it("RsaEncryptNullData")
	
	it("RsaEncryptEmptyData", function () {
		var error = undefined;
		var clearText = hex2abv("");
		var encrypted = undefined;
		var decrypted = undefined;

		runs(function () {
			var encryptOp = nfCrypto.encrypt("RSAES-PKCS1-v1_5", PUBKEY, clearText);
			encryptOp.onerror = function (e) {
				error = "ERROR: " + e.target.result;
			};
			encryptOp.oncomplete = function (e) {
				encrypted = e.target.result;
			};
		});

		waitsFor(function () {
			return encrypted || error;
		});

		runs(function () {
			expect(error).toBe("ERROR: invalid base64 encoding");
			expect(encrypted).toBeUndefined();
		});
	});//it("RsaEncryptEmptyData")
	
	it("RsaDecryptNullData", function () {
		var error = undefined;
		var clearText = hex2abv("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
		var encrypted = undefined;
		var decrypted = undefined;

		runs(function () {
			// encrypt clearText with the public key
			var encryptOp = nfCrypto.encrypt("RSAES-PKCS1-v1_5", PUBKEY, clearText);
			encryptOp.onerror = function (e) {
				error = "ERROR :: " + e.target.result;
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
			expect(encrypted).not.toBeNull();
			expect(encrypted).toNotBe(clearText);
		});

		runs(function () {
			//Making encrypted data null
			encrypted = null;
			var encryptOp = nfCrypto.decrypt("RSAES-PKCS1-v1_5", PRIVKEY, encrypted);
			encryptOp.onerror = function (e) {
				error = "ERROR: " + e.target.result;
			};
			encryptOp.oncomplete = function (e) {
				decrypted = e.target.result;
			};
		});

		waitsFor(function () {
			return decrypted || error;
		});

		runs(function () {
			expect(error).toBe("ERROR: bad or missing parameter");
			expect(decrypted).toBeUndefined();
		});
	});//it("RsaDecryptNullData")
	
	it("RsaDecryptEmptyData", function () {
		var error = undefined;
		var clearText = hex2abv("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
		var encrypted = undefined;
		var decrypted = undefined;

		runs(function () {
			// encrypt clearText with the public key
			var encryptOp = nfCrypto.encrypt("RSAES-PKCS1-v1_5", PUBKEY, clearText);
			encryptOp.onerror = function (e) {
				error = "ERROR :: " + e.target.result;
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
			expect(encrypted).not.toBeNull();
			expect(encrypted).toNotBe(clearText);
		});

		runs(function () {
			//Making encrypted data null
			encrypted = hex2abv("");
			var encryptOp = nfCrypto.decrypt("RSAES-PKCS1-v1_5", PRIVKEY, encrypted);
			encryptOp.onerror = function (e) {
				error = "ERROR: " + e.target.result;
			};
			encryptOp.oncomplete = function (e) {
				decrypted = e.target.result;
			};
		});

		waitsFor(function () {
			return decrypted || error;
		});

		runs(function () {
			expect(error).toBe("ERROR: invalid base64 encoding");
			expect(decrypted).toBeUndefined();
		});
	});//it("RsaDecryptEmptyData")
	
	it("RsaEncryptIncorrectPubKey", function () {
		var error = undefined;
		var clearText = hex2abv("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
		var encrypted = undefined;
		var decrypted = undefined;

		runs(function () {
			//Using incorrect pub key
			PUBKEY.handle += 1;
			var encryptOp = nfCrypto.encrypt("RSAES-PKCS1-v1_5", PUBKEY, clearText);
			encryptOp.onerror = function (e) {
				error = "ERROR: " + e.target.result;
			};
			encryptOp.oncomplete = function (e) {
				encrypted = e.target.result;
			};
		});

		waitsFor(function () {
			return encrypted || error;
		});

		runs(function () {
			expect(error).toBeDefined("ERROR: incorrect key or dh session handle");
			expect(encrypted).toBeUndefined();
		});
	});//it("RsaEncryptIncorrectPubKey")
	

	it("RsaEncryptIncorrectPrivKey", function () {
		var error = undefined;
		var clearText = hex2abv("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
		var encrypted = undefined;
		var decrypted = undefined;

		runs(function () {
			var encryptOp = nfCrypto.encrypt("RSAES-PKCS1-v1_5", PUBKEY, clearText);
			encryptOp.onerror = function (e) {
				error = "ERROR: " + e.target.result;
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
			expect(encrypted).not.toBeNull();
			expect(encrypted).not.toBe(clearText);
		});

		runs(function () {
			error = undefined;
			//Using incorrect priv key
			PRIVKEY.handle += 1;
			var encryptOp = nfCrypto.decrypt("RSAES-PKCS1-v1_5", PRIVKEY, encrypted);
			encryptOp.onerror = function (e) {
				error = "ERROR: " + e.target.result;
			};
			encryptOp.oncomplete = function (e) {
				decrypted = e.target.result;
			};
		});

		waitsFor(function () {
			return decrypted || error;
		});

		runs(function () {
			expect(error).toBeDefined("ERROR: incorrect key or dh session handle");
			expect(decrypted).toBeUndefined();
		});
	});//it("RsaEncryptIncorrectPrivKey")
	
	

});