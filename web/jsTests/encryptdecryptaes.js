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

describe("EncryptDecryptAES", function () {
	var KEY;
		
	beforeEach(function () {
		var error;
		runs(function () {
			var op = nfCrypto.importKey(
					"raw",
					new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F]),
					"AES-GCM",
					true,
					["encrypt", "decrypt"]
			);
			op.onerror = function (e) {
				error = "ERROR :: " + e.target.result
			};
			op.oncomplete = function (e) {
				KEY = e.target.result;
			};
		});

		waitsFor(function () {
			return KEY || error;
		});

		runs(function () {
			expect(error).toBeUndefined();
			expect(KEY).toBeDefined();
		});
	});

	afterEach(function () {
		KEY = undefined;
	});

	it("EncryptDecryptHappyPath", function () {
		var error = undefined;
		var encrypted = undefined;
		var decrypted = undefined;
		var iv = hex2abv("562e17996d093d28ddb3ba695a2e6f58"),
		clearText_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		clearText = hex2abv(clearText_hex);

		runs(function () {
			error = undefined;
			var encryptOp = nfCrypto.encrypt({
				name: "AES-CBC",
				params: { iv: iv }
			}, KEY, clearText);
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
			expect(encrypted).not.toBeNull();
			expect(encrypted).toNotBe(clearText);
		});

		runs(function () {
			error = undefined;
			var decryptOp = nfCrypto.decrypt({
				name: "AES-CBC",
				params: { iv: iv }
			}, KEY, encrypted);
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
			expect(abv2hex(decrypted)).toBe(clearText_hex);
		});
	});//it("EncryptDecryptHappyPath")
	
	it("EncryptDecryptLargeData", function () {
		var error = undefined;
		var encrypted = undefined;
		var decrypted = undefined;
		var iv = hex2abv("562e17996d093d28ddb3ba695a2e6f58")
		var clearText_notHex = "eyJtZXNzYWdlaWQiOjQ2MDQwODM3Niwibm9ucmVwbGF5YWJsZSI6ZmFsc2UsInJlbmV3YWJsZSI6dHJ1ZSwiY2FwYWJpbGl0aWVzIjp7ImNvbXByZXNzaW9uYWxnb3MiOlsiTFpXIl19LCJrZXlyZXF1ZXN0ZGF0YSI6W3sic2NoZW1lIjoiQVNZTU1FVFJJQ19XUkFQUEVEIiwia2V5ZGF0YSI6eyJrZXlwYWlyaWQiOiJyc2FLZXlwYWlySWQiLCJtZWNoYW5pc20iOiJSU0EiLCJwdWJsaWNrZXkiOiJUVWxIU2tGdlIwSkJUMWxYVXpZMk5ubEhjazU1U0Vkbk4yMHZaMlJuYjBKMVJGaHpLM0JOU1dWTGNVNVBkMlZKYW5selRYSjRTVTk0WjJ4TVMzRkVOa2xsV2pkd01VSmlVRVY0V0ZoS2EzTlpOR2RUVGtNM01FTmxRVUpFVVRkRmIzRmlXR1V3UkRsVVZFNU9MMHBOVW01SmNtVnVaWFU1TldOeE5ucGhNSGcxVjFkemEzWkxTRTh6Y21GVk9YZEZjQzlaUlZNM2JWVnphMmx5V2s1QkswWlVUVlJhT1RKalUxaDZXUzlyTUZFMlpHVTNRV2ROUWtGQlJUMD0ifX1dfQ==";
		//Converting from base64 to abv
		var clearText = base64.parse(clearText_notHex);
		
		runs(function () {
			error = undefined;
			var encryptOp = nfCrypto.encrypt({
				name: "AES-CBC",
				params: { iv: iv }
			}, KEY, clearText);
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
			expect(encrypted).not.toBeNull();
			expect(encrypted).not.toBe(clearText_notHex);
		});

		runs(function () {
			error = undefined;
			var decryptOp = nfCrypto.decrypt({
				name: "AES-CBC",
				params: { iv: iv }
			}, KEY, encrypted);
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
			expect(base64.stringify(decrypted)).toBe(clearText_notHex);
		});
	});//it("EncryptDecryptLargeData")
	
	
	//Uses different iv for decryption, expect decrypted clear text to be different
	//from original clear text
	it("DifferentDecryptIV", function () {
		var error = undefined;
		var encrypted = undefined;
		var decrypted = undefined;
	
		var encrypt_iv = hex2abv("562e17996d093d28ddb3ba695a2e6f58");
		var decrypt_iv = hex2abv("b63e541bc9ece19a1339df4f8720dcc3");
		var clearText_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
		var clearText = hex2abv(clearText_hex);

		runs(function () {
			error = undefined;
			var encryptOp = nfCrypto.encrypt({
				name: "AES-CBC",
				params: { iv: encrypt_iv }
			}, KEY, clearText);
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
			expect(encrypted).not.toBeNull();
			expect(encrypted).toNotBe(clearText);
		});

		runs(function () {
			error = undefined;
			var decryptOp = nfCrypto.decrypt({
				name: "AES-CBC",
				params: { iv: decrypt_iv }
			}, KEY, encrypted);
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
			expect(abv2hex(decrypted)).not.toEqual(clearText_hex);
		});
	});//it("DifferentDecryptIV")
	
	
	//Change encrypted data after encryption expect decryption to not match clear text
	it("EncryptionDecryptionMisMatch", function () {
		var error = undefined;
		var encrypted = undefined;
		var decrypted = undefined;
		var iv = hex2abv("562e17996d093d28ddb3ba695a2e6f58");
		var clearText_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
		var clearText = hex2abv(clearText_hex);

		runs(function () {
			var encryptOp = nfCrypto.encrypt({
				name: "AES-CBC",
				params: { iv: iv }
			}, KEY, clearText);
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
			expect(encrypted).not.toBeNull();
			expect(encrypted).toNotBe(clearText);
		});

		runs(function () {
			error = undefined;
			//Manipulating encrypted data
			encrypted[0] = encrypted[0] + 1;
			var decryptOp = nfCrypto.decrypt({
				name: "AES-CBC",
				params: { iv: iv }
			}, KEY, encrypted);
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
			expect(abv2hex(decrypted)).not.toEqual(clearText_hex);
			
		});
	});//it("EncryptionDecryptionMisMatch")
	
	it("EncryptNullData", function () {
		var error = undefined;
		var encrypted = undefined;
		var decrypted = undefined;
		var iv = hex2abv("562e17996d093d28ddb3ba695a2e6f58");
		var clearText = null;

		runs(function () {
			error = undefined;
			var encryptOp = nfCrypto.encrypt({
				name: "AES-CBC",
				params: { iv: iv }
			}, KEY, clearText);
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
			expect(error).toBe("ERROR");
			expect(encrypted).toBeUndefined();
		});

	});//it("EncryptNullData")
	
	it("EncryptEmptyData", function () {
		var error = undefined;
		var encrypted = undefined;
		var decrypted = undefined;
		var iv = hex2abv("562e17996d093d28ddb3ba695a2e6f58");
		var clearText = hex2abv("");

		runs(function () {
			error = undefined;
			var encryptOp = nfCrypto.encrypt({
				name: "AES-CBC",
				params: { iv: iv }
			}, KEY, clearText);
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
			expect(error).toBe("ERROR");
			expect(encrypted).toBeUndefined();
		});

	});//it("EncryptEmptyData")
	
	it("DecryptNullData", function () {
		var error = undefined;
		var encrypted = undefined;
		var decrypted = undefined;
		var iv = hex2abv("562e17996d093d28ddb3ba695a2e6f58"),
		clearText_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		clearText = hex2abv(clearText_hex);

		runs(function () {
			error = undefined;
			var encryptOp = nfCrypto.encrypt({
				name: "AES-CBC",
				params: { iv: iv }
			}, KEY, clearText);
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
			expect(encrypted).not.toBeNull();
			expect(encrypted).toNotBe(clearText);
		});

		runs(function () {
			error = undefined;
			//Making encrypted null
			encrypted = null;
			var decryptOp = nfCrypto.decrypt({
				name: "AES-CBC",
				params: { iv: iv }
			}, KEY, encrypted);
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
			expect(error).toBe("ERROR");
			expect(decrypted).toBeUndefined();
		});
	});//it("DecryptNullData")
	
	it("DecryptEmptyData", function () {
		var error = undefined;
		var encrypted = undefined;
		var decrypted = undefined;
		var iv = hex2abv("562e17996d093d28ddb3ba695a2e6f58"),
		clearText_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		clearText = hex2abv(clearText_hex);

		runs(function () {
			error = undefined;
			var encryptOp = nfCrypto.encrypt({
				name: "AES-CBC",
				params: { iv: iv }
			}, KEY, clearText);
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
			expect(encrypted).not.toBeNull();
			expect(encrypted).toNotBe(clearText);
		});

		runs(function () {
			error = undefined;
			//Making encrypted empty
			encrypted = hex2abv("");
			var decryptOp = nfCrypto.decrypt({
				name: "AES-CBC",
				params: { iv: iv }
			}, KEY, encrypted);
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
			expect(error).toBe("ERROR: invalid base64 encoding");
			expect(decrypted).toBeUndefined();
		});
	});//it("DecryptNullData")
	
	//RSASSA_PKCS1_V1_5 is a valid algo but not supported for encryption
	it("EncryptInvalidAlgoType", function () {
		var error = undefined;
		var encrypted = undefined;
		var decrypted = undefined;
		var iv = hex2abv("562e17996d093d28ddb3ba695a2e6f58");
		var clearText_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
		var clearText = hex2abv(clearText_hex);

		runs(function () {
			error = undefined;
			var encryptOp = nfCrypto.encrypt({
				name: "RSASSA_PKCS1_V1_5",
				params: { iv: iv }
			}, KEY, clearText);
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
			expect(error).toBe("ERROR");
			expect(encrypted).toBeUndefined();
		});

	});//it(""EncryptInvalidAlgoType")
	
	//aes-cbc produces an enum mismatch
	it("EncryptInvalidAlgo", function () {
		var error = undefined;
		var encrypted = undefined;
		var decrypted = undefined;
		var iv = hex2abv("562e17996d093d28ddb3ba695a2e6f58");
		var clearText_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
		var clearText = hex2abv(clearText_hex);

		runs(function () {
			error = undefined;
			var encryptOp = nfCrypto.encrypt({
				name: "aes-cbc",
				params: { iv: iv }
			}, KEY, clearText);
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
			expect(error).toBe("ERROR");
			expect(encrypted).toBeUndefined();
		});

	});//it(""EncryptInvalidAlgoType")
	
	it("EncryptInvalidKey", function () {
		var error = undefined;
		var encrypted = undefined;
		var decrypted = undefined;
		var iv = hex2abv("562e17996d093d28ddb3ba695a2e6f58"),
		clearText_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		clearText = hex2abv(clearText_hex);

		runs(function () {
			error = undefined;
			KEY += 1;
			var encryptOp = nfCrypto.encrypt({
				name: "AES-CBC",
				params: { iv: iv }
			}, KEY, clearText);
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
			expect(error).toBeDefined("ERROR");
			expect(encrypted).toBeUndefined();
		});

	});//it("EncryptInvalidKey")
	
	it("DecryptInvalidKey", function () {
		var error = undefined;
		var encrypted = undefined;
		var decrypted = undefined;
		var iv = hex2abv("562e17996d093d28ddb3ba695a2e6f58"),
		clearText_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		clearText = hex2abv(clearText_hex);

		runs(function () {
			error = undefined;
			var encryptOp = nfCrypto.encrypt({
				name: "AES-CBC",
				params: { iv: iv }
			}, KEY, clearText);
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
			expect(encrypted).not.toBeNull();
			expect(encrypted).toNotBe(clearText);
		});

		runs(function () {
			error = undefined;
			KEY += 1;
			var decryptOp = nfCrypto.decrypt({
				name: "AES-CBC",
				params: { iv: iv }
			}, KEY, encrypted);
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
			expect(error).toBeDefined("ERROR");
			expect(decrypted).toBeUndefined();
		});
	});//it("DecryptInvalidKey")
	
	
	//8 byte IV is not allowed 16 bytes required by algo
	//Commenting out the test case since an assert is called and Chrome crashes
	//TODO: Uncomment when assert is taken out of debug builds
	it("EncryptShortIV", function () {
		var error = undefined;
		var encrypted = undefined;
		var decrypted = undefined;
		var short_iv = hex2abv("ddb3ba695a2e6f58");
		var clearText_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
		var clearText = hex2abv(clearText_hex);

		runs(function () {
			error = undefined;
			var encryptOp = nfCrypto.encrypt({
				name: "AES-CBC",
				params: { iv: short_iv }
			}, KEY, clearText);
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
			expect(error).toBe("ERROR");
			expect(encrypted).toBeUndefined();
		});

	});//it(""EncryptInvalidAlgoType")
	
});//describe