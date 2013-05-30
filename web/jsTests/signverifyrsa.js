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

describe("SignVerifyRSA", function () {
    var PUBKEY = undefined;
	var PRIVKEY = undefined;
	var DATA = hex2abv("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
	
	//Generate keys for each test
	beforeEach(function () {
		// generate the keys before each test
		var fermatF4 = new Uint8Array([0x01, 0x00, 0x01]);
		var error;

		runs(function () {
			var genOp = nfCrypto.generateKey({
				name: "RSASSA-PKCS1-v1_5",
				params: {
					modulusLength: 512,
					publicExponent: fermatF4,
				},
				//TODO: Add specific tests to check default values and see that 
				//they hold true wrt C++
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
		});//beforeEach

		afterEach(function () {
			PUBKEY = undefined;
			PRIVKEY = undefined;
		});

		it("RsaSignVerifyHappyPath", function () {
			var error = undefined;
			var signature = undefined;
			var verified = undefined;

			// sign data with the private key
			runs(function () {
				error = undefined;
				var signOp = nfCrypto.sign({
					name: "RSASSA-PKCS1-v1_5",
					params: { hash: "SHA-256", },
				}, PRIVKEY, DATA);
				signOp.onerror = function (e) {
					error = "ERROR :: " + e.target.result;
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

			// verify data with the public key
			runs(function () {
				error = undefined;
				var verifyOp = nfCrypto.verify({
					name: "RSASSA-PKCS1-v1_5",
					params: { hash: "SHA-256", },
				}, PUBKEY, signature, DATA);
				verifyOp.onerror = function (e) {
					error = "ERROR :: " + e.target.result;
				};
				verifyOp.oncomplete = function (e) {
					verified = e.target.result;
				};
			});

			waitsFor(function () {
				return (verified != undefined) || error;
			});

			runs(function () {
				expect(error).toBeUndefined();
				expect(verified).toBe(true);
			});
		});//it("RsaSignVerifyHappyPath")
		
		//There is no limit on size of data to sign/verify since it has SHA performed on it
		it("SignVerifyLargeData", function () {
			var error = undefined;
			var signature = undefined;
			var verified = undefined;
			var DATA = base64.parse("eyJtZXNzYWdlaWQiOjQ2MDQwODM3Niwibm9ucmVwbGF5YWJsZSI6ZmFsc2UsInJlbmV3YWJsZSI6dHJ1ZSwiY2FwYWJpbGl0aWVzIjp7ImNvbXByZXNzaW9uYWxnb3MiOlsiTFpXIl19LCJrZXlyZXF1ZXN0ZGF0YSI6W3sic2NoZW1lIjoiQVNZTU1FVFJJQ19XUkFQUEVEIiwia2V5ZGF0YSI6eyJrZXlwYWlyaWQiOiJyc2FLZXlwYWlySWQiLCJtZWNoYW5pc20iOiJSU0EiLCJwdWJsaWNrZXkiOiJUVWxIU2tGdlIwSkJUMWxYVXpZMk5ubEhjazU1U0Vkbk4yMHZaMlJuYjBKMVJGaHpLM0JOU1dWTGNVNVBkMlZKYW5selRYSjRTVTk0WjJ4TVMzRkVOa2xsV2pkd01VSmlVRVY0V0ZoS2EzTlpOR2RUVGtNM01FTmxRVUpFVVRkRmIzRmlXR1V3UkRsVVZFNU9MMHBOVW01SmNtVnVaWFU1TldOeE5ucGhNSGcxVjFkemEzWkxTRTh6Y21GVk9YZEZjQzlaUlZNM2JWVnphMmx5V2s1QkswWlVUVlJhT1RKalUxaDZXUzlyTUZFMlpHVTNRV2ROUWtGQlJUMD0ifX1dfQ==");


			// sign data with the private key
			runs(function () {
				error = undefined;
				var signOp = nfCrypto.sign({
					name: "RSASSA-PKCS1-v1_5",
					params: { hash: "SHA-256", },
				}, PRIVKEY, DATA);
				signOp.onerror = function (e) {
					error = "ERROR :: " + e.target.result;
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

			// verify data with the public key
			runs(function () {
				error = undefined;
				var verifyOp = nfCrypto.verify({
					name: "RSASSA-PKCS1-v1_5",
					params: { hash: "SHA-256", },
				}, PUBKEY, signature, DATA);
				verifyOp.onerror = function (e) {
					error = "ERROR :: " + e.target.result;
				};
				verifyOp.oncomplete = function (e) {
					verified = e.target.result;
				};
			});

			waitsFor(function () {
				return (verified != undefined) || error;
			});

			runs(function () {
				expect(error).toBeUndefined();
				expect(verified).toBe(true);
			});
		});//it("RsaSignVerifyHappyPath")


		//Using encryption algo for verify should fail
		it("VerifyInvalidAlgoType", function () {
			var error = undefined;
			var verified = undefined;
			var signature = undefined;

			// sign algo is correct
			runs(function () {
				error = undefined;
				var signOp = nfCrypto.sign({
					name: "RSASSA-PKCS1-v1_5",
					params: { hash: "SHA-256", },
				}, PRIVKEY, DATA);
				signOp.onerror = function (e) {
					error = "ERROR :: " + e.target.result;
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

			runs(function () {
				error = undefined;
				//using encryption algo for verify		
				var verifyOp = nfCrypto.verify({
					name: "RSAES_PKCS1_V1_5",
					params: { hash: "SHA-256", },
				}, PUBKEY, signature, DATA);
				verifyOp.onerror = function (e) {
					error = "ERROR: " + e.target.result;
				}
				verifyOp.oncomplete = function (e) {
					verified = e.target.result;
				};
			});

			waitsFor(function () {
				return verified !== undefined || error;
			});

			runs(function () {
				expect(error).toBe("ERROR: unknown algorithm");
				expect(verified).toBeUndefined();
			});
		});//it("VerifyInvalidAlgoType")

		it("SignEmptyData", function () {
			var error = undefined;
			var data = hex2abv("");
			var signature = undefined;

			//sign data with the private key
			runs(function () {
				var signOp = nfCrypto.sign({
					name: "RSASSA-PKCS1-v1_5",
					params: { hash: "SHA-256", },
				}, PRIVKEY, data);
				signOp.onerror = function (e) {
					error = "ERROR: " + e.target.result;
				};
				signOp.oncomplete = function (e) {
					signature = e.target.result;
				};
			});

			waitsFor(function () {
				return signature || error;
			});

			runs(function () {
				expect(error).toBe("ERROR: invalid base64 encoding");
				expect(signature).toBeUndefined();
			});
		});//it("SignEmptyData")

		it("SignNullData", function () {
			var error = undefined;
			var data = null;
			var signature = undefined;

			//sign data with the private key
			runs(function () {
				var signOp = nfCrypto.sign({
					name: "RSASSA-PKCS1-v1_5",
					params: { hash: "SHA-256", },
				}, PRIVKEY, data);
				signOp.onerror = function (e) {
					error = "ERROR: " + e.target.result;
				};
				signOp.oncomplete = function (e) {
					signature = e.target.result;
				};
			});

			waitsFor(function () {
				return signature || error;
			});

			runs(function () {
				expect(error).toBe("ERROR: bad or missing parameter");
				expect(signature).toBeUndefined();
			});
		});//it("SignNullData")

		it("SignInvalidAlgo", function () {
			var error = undefined;
			var signature = undefined;

			//sign data with the private key
			runs(function () {
				var signOp = nfCrypto.sign({
					name: "RSASSA",
					params: { hash: "SHA-256", },
				}, PRIVKEY, DATA);
				signOp.onerror = function (e) {
					error = "ERROR: " + e.target.result;
				};
				signOp.oncomplete = function (e) {
					signature = e.target.result;
				};
			});

			waitsFor(function () {
				return signature || error;
			});

			runs(function () {
				expect(error).toBe("ERROR: unknown algorithm");
				expect(signature).toBeUndefined();
			});
		});//it("SignInvalidAlgo")

		//Using encryption algo for signing should result in failure
		it("SignInvalidAlgoType", function () {
			var error = undefined;
			var signature = undefined;

			runs(function () {
				var signOp = nfCrypto.sign({
					name: "RSAES_PKCS1_V1_5",
					params: { hash: "SHA-256", },
				}, PRIVKEY, DATA);
				signOp.onerror = function (e) {
					error = "ERROR: " + e.target.result;
				};
				signOp.oncomplete = function (e) {
					signature = e.target.result;
				};
			});

			waitsFor(function () {
				return signature || error;
			});

			runs(function () {
				//TODO: Check if a different type of error should be returned
				expect(error).toBe("ERROR: unknown algorithm");
				expect(signature).toBeUndefined();
			});
		});//it("SignInvalidAlgoType")

		
	it("InvalidRsaSignature", function () {
		var error = undefined;
		var verified = undefined;
		var signature = undefined;

			// sign data with the private key
		runs(function () {
				error = undefined;
				var signOp = nfCrypto.sign({
					name: "RSASSA-PKCS1-v1_5",
					params: { hash: "SHA-256", },
				}, PRIVKEY, DATA);
				signOp.onerror = function (e) {
					error = "ERROR :: " + e.target.result;
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

			runs(function () {
				error = undefined;
				signature[0] = signature[0] + 1;
				var verifyOp = nfCrypto.verify({
					name: "RSASSA-PKCS1-v1_5",
					params: { hash: "SHA-256", },
				}, PUBKEY, signature, DATA);
				verifyOp.onerror = function (e) {
					error = "ERROR :: " + e.target.result;
				};
				verifyOp.oncomplete = function (e) {
					verified = e.target.result;
				}
			});

			waitsFor(function () {
				return verified !== undefined || error;
			});

			runs(function () {
				expect(error).toBeUndefined();
				expect(verified).toBe(false);
			});
	});//it("InvalidRsaSignature")
	
	it("SignInvalidPrivateKey", function () {
		var error = undefined;
		var verified = undefined;
		var signature = undefined;
        PRIVKEY.handle = 0;
			// sign data with the private key
		runs(function () {
			var signOp = nfCrypto.sign({
					name: "RSASSA-PKCS1-v1_5",
					params: { hash: "SHA-256", },
			}, PRIVKEY, DATA);
			signOp.onerror = function (e) {
				error = "ERROR: " + e.target.result;
			};
			signOp.oncomplete = function (e) {
				signature = e.target.result;
			};
		});

		waitsFor(function () {
			return signature || error;
		});

		runs(function () {
			expect(error).toBe("ERROR: invalid key or dh session handle");
			expect(signature).toBeUndefined();
		});

	});//it("SignInvalidPrivateKey")
	
	it("VerifyInvalidPublicKey", function () {
		var error = undefined;
		var verified = undefined;
		var signature = undefined;
        
		runs(function () {
			var signOp = nfCrypto.sign({
					name: "RSASSA-PKCS1-v1_5",
					params: { hash: "SHA-256", },
			}, PRIVKEY, DATA);
			signOp.onerror = function (e) {
				error = "ERROR: " + e.target.result;
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
		
		runs(function () {
			error = undefined;
			PUBKEY.handle = 0;
			var verifyOp = nfCrypto.verify({
				name: "RSASSA-PKCS1-v1_5",
				params: { hash: "SHA-256", },
			}, PUBKEY, signature, DATA);
			verifyOp.onerror = function (e) {
				error = "ERROR: " + e.target.result;
			};
			verifyOp.oncomplete = function (e) {
				verified = e.target.result;
			};
		});

		waitsFor(function () {
			return (verified != undefined) || error;
		});

		runs(function () {
			expect(error).toBe("ERROR: invalid key or dh session handle");
			expect(verified).toBeUndefined();
		});

	});//it("SignInvalidPrivateKey")
	
});//describe("SignVerifyRSA")


