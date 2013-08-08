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

describe("importexportjwk", function () {

	//Globals
	var OPINDEX = 0;
	var INDEXVALUE = 0;
	var LISTOFTESTS = [

	                   {
	                	   test: "ImportExportHappyPathJWKKey",
	                	   keyFormat: "jwk",
	                	   algo: { name: "RSAES-PKCS1-v1_5" },
	                	   usages: ["encrypt", "decrypt"],
	                	   extractable: true,
	                	   type: "public",
	                	   result: "pass"
	                   },
	                   {
	                	   //Export key still works because JWK obj has extractable true
	                	   test: "ImpportExportJWKNonExtractable",
	                	   keyFormat: "jwk",
	                	   algo: { name: "RSAES-PKCS1-v1_5" },
	                	   usages: ["encrypt", "decrypt"],
	                	   extractable: false,
	                	   type: "public",
	                	   result: "pass"
	                   },

	                   { //Passes since the usage should be extracted from the jwk(which is encrypt/decrypt)
	                	   test: "ImportJWKInvalidUsage",
	                	   keyFormat: "jwk",
	                	   algo: { name: "RSAES-PKCS1-v1_5" },
	                	   usages: ["derive"],
	                	   extractable: true,
	                	   type: "public",
	                	   importKey: true
	                   },

	                   {
	                	   ///Passes since the algo RSA1_5 is embedded in the jwk
	                	   test: "ImportJWKInvalidAlgo",
	                	   keyFormat: "jwk",
	                	   algo: { name: "invalidAlgorithmName" },
	                	   usages: ["encrypt", "decrypt"],
	                	   extractable: true,
	                	   type: "public",
	                	   result: "pass"
	                   },

	                   {
	                	   //Passes even though SHA-384 is not a valid import algo
	                	   //because jwk has the correct algo
	                	   test: "ImportJWKIncorrectAlgo",
	                	   keyFormat: "jwk",
	                	   algo: { name: "SHA-384" },
	                	   usages: ["encrypt", "decrypt"],
	                	   extractable: true,
	                	   type: "public",
	                	   result: "pass"
	                   },
	                   {
	                	   //Specifying raw instead of jwk
	                	   test: "ImportJWKIncorrectKeyFormat",
	                	   keyFormat: "raw",
	                	   algo: { name: "PKCS1-v1_5" },
	                	   usages: ["encrypt", "decrypt"],
	                	   extractable: true,
	                	   type: "public",
	                	   importKey: false
	                   },
	                   {   //Import will pass export will fail
	                	   test: "ExportJWKIncorrectKeyFormat",
	                	   keyFormat: "jwk",
	                	   exportFormat: "pkcs8",
	                	   algo: { name: "RSAES-PKCS1-v1_5" },
	                	   usages: ["encrypt", "decrypt"],
	                	   extractable: true,
	                	   type: "public",
	                	   exportKey: false
	                   },

	                   {	//Manipulation of key for import is done below
	                	   test: "ImportJWKInvalidKey",
	                	   keyFormat: "jwk",
	                	   algo: { name: "RSAES-PKCS1-v1_5" },
	                	   usages: ["encrypt", "decrypt"],
	                	   extractable: true,
	                	   type: "public",
	                	   importKey: false
	                   },

	                   {   //Manipulation of key for export is done below
	                	   //Passes import fails export
	                	   test: "ExportJWKInvalidKey",
	                	   keyFormat: "jwk",
	                	   algo: { name: "RSAES-PKCS1-v1_5" },
	                	   usages: ["encrypt", "decrypt"],
	                	   extractable: true,
	                	   type: "public",
	                	   exportKey: false
	                   }
	                   ];

	function wrapperForTest(OPINDEX) {
		it(LISTOFTESTS[OPINDEX].test, function () {
			INDEXVALUE = LISTOFTESTS[OPINDEX];
			var error = undefined;
			var key = undefined;
			var exportedJwkKeyData = undefined;
			var jwkKeyData = undefined;

			runs(function () {
				error = undefined;
				var op = undefined;
				try {
					if (INDEXVALUE.test == "ImportJWKInvalidKey") {
						var jwkBadData = latin1.parse(JSON.stringify({
							//Missing kty field
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
							use: "enc"
						}));
						op = nfCrypto.importKey(INDEXVALUE.keyFormat, jwkBadData, INDEXVALUE.algo, INDEXVALUE.extractable, INDEXVALUE.usages);
					} else {
						// key data is Uint8Array which is Latin1 encoded "{n: base64, e: base64}" json string
						jwkKeyData = latin1.parse(JSON.stringify({
							alg: "RSA1_5",
							kty: "RSA",
							use: "enc",
							extractable: true,
							n: base64.stringifyUrlSafe(base16.parse(
									"a8b3b284af8eb50b387034a860f146c4919f318763cd6c55" +
									"98c8ae4811a1e0abc4c7e0b082d693a5e7fced675cf46685" +
									"12772c0cbc64a742c6c630f533c8cc72f62ae833c40bf258" +
									"42e984bb78bdbf97c0107d55bdb662f5c4e0fab9845cb514" +
									"8ef7392dd3aaff93ae1e6b667bb3d4247616d4f5ba10d4cf" +
									"d226de88d39f16fb"
							)),
							e: base64.stringifyUrlSafe(base16.parse("010001")),


						}));
						op = nfCrypto.importKey(INDEXVALUE.keyFormat, jwkKeyData, INDEXVALUE.algo, INDEXVALUE.extractable, INDEXVALUE.usages);
					}

					op.onerror = function (e) {
						error = "ERROR";
					};
					op.oncomplete = function (e) {
						key = e.target.result;
					};
				}
				catch(e) {
					error = "ERROR";
				}
			});

			waitsFor(function () {
				return key || error;
			});

			runs(function () {
				if (INDEXVALUE.importKey == false) {
					expect(error).toBeDefined();
					expect(key).toBeUndefined();
				} else {
					expect(error).toBeUndefined();
					//Doing checks on keys to validate Key structure
					if ((INDEXVALUE.test == "ImportJWKIncorrectAlgo") || (INDEXVALUE.test == "ImportJWKInvalidAlgo")) {
						expect(key.algorithm.name).not.toEqual(INDEXVALUE.algo.name);
					} else {
						expect(key.algorithm.name).toEqual(INDEXVALUE.algo.name);
					}
					if (INDEXVALUE.test == "ImpportExportJWKNonExtractable") {
						expect(key.extractable).toBeTruthy();
					} else {
						expect(key.extractable).toEqual(INDEXVALUE.extractable);
					}

					if (INDEXVALUE.test == "ImportJWKInvalidUsage") {
						expect(key.keyUsage[0]).toEqual("encrypt");
					} else if(INDEXVALUE.usages.length > 1) {
						expect(key.keyUsage[0]).toEqual(INDEXVALUE.usages[0]);
						expect(key.keyUsage[1]).toEqual(INDEXVALUE.usages[1]);
					} else {
						expect(key.keyUsage[0]).toEqual(INDEXVALUE.usages[0]);
					}
					expect(key.type).toEqual(INDEXVALUE.type);
					//Handle is how C++ correlates keys with JS
					//0 implies invalid key
					expect(key.handle).not.toEqual(0);
				}

			});

			runs(function () {
				error = undefined;
				exportedJwkKeyData = undefined;
				var op = undefined;
				try {
					if (INDEXVALUE.test == "ExportJWKIncorrectKeyFormat") {
						op = nfCrypto.exportKey(INDEXVALUE.exportFormat, key);
					} else if (INDEXVALUE.test == "ExportJWKInvalidKey") {
						key = new Uint8Array([]);
						op = nfCrypto.exportKey(INDEXVALUE.keyFormat, key);
					} else {
						//Default case
						op = nfCrypto.exportKey(INDEXVALUE.keyFormat, key);
					}

					op.onerror = function (e) {
						error = "ERROR";
					};
					op.oncomplete = function (e) {
						exportedJwkKeyData = e.target.result;
					};
				} catch(e) {
					error = "ERROR";
				}
			});

			waitsFor(function () {
				return error || exportedJwkKeyData;
			});

			runs(function () {
				if (INDEXVALUE.importKey == false || INDEXVALUE.exportKey == false) {
					expect(error).toBeDefined();
					expect(exportedJwkKeyData).toBeUndefined();
				} else {
					expect(error).toBeUndefined();
					expect(JSON.parse(latin1.stringify(exportedJwkKeyData))).toEqual(JSON.parse(latin1.stringify(jwkKeyData)));
				}
			});
		});//it
	}//function wrapperForTest
	for(OPINDEX = 0; OPINDEX < LISTOFTESTS.length; OPINDEX++) {
		wrapperForTest(OPINDEX);
	}
});//describe("importexportjwk")


describe("importexportjwkerrors", function () {

	//Import/export -tamper key then import again
	it("ImportMalformedJwk", function () {
		//Globals
		var error = undefined,
		key = undefined,
		exportedData = undefined,
		mangledKey = undefined;
		var key128 = new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F]);
		var key256 = new Uint8Array(key128.length * 2);
		key256.set(key128);
		key256.set(key128, key128.length);

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
			var op = nfCrypto.importKey("jwk", jwk3, { name: "RSAES-PKCS1-v1_5" }, true);
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
		});
		//Export
		runs(function () {
			error = undefined;
			var op = nfCrypto.exportKey("jwk", key);
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

		//Tamper before importing
		runs(function () {
			exportedData[0] = exportedData[0] ^ 0xFF;
			error = undefined;
			var op = nfCrypto.importKey("jwk", exportedData, { name: "RSAES-PKCS1-v1_5" }, true);
			op.onerror = function (e) {
				error = "ERROR";
			};
			op.oncomplete = function (e) {
				mangledKey = e.target.result;
			};
		})
		waitsFor(function () {
			return mangledKey || error;
		});
		runs(function () {
			expect(error).toBeDefined();
			expect(mangledKey).toBeUndefined();
		});

	});//it("ImportExportHMACJwk")
});

describe("jwkdifferentalgos", function () {
	//Globals
	var OPINDEX = 0;
	var INDEXVALUE = 0;
	var KEY128 = new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F]);
	var KEY256 = new Uint8Array(KEY128.length * 2);
	var KEY384 = new Uint8Array(KEY128.length * 3);
	var KEY512 = new Uint8Array(KEY128.length * 4);
	KEY256.set(KEY128, KEY128.length);
	KEY384.set(KEY256, KEY128.length);
	KEY512.set(KEY384, KEY128.length);

	var FERMATF4 = new Uint8Array([0x01, 0x00, 0x01]);

	var LISTOFTESTS = [
	                   {
	                	   test: "ImportJWK_A128CBC",
	                	   algo: "A128CBC",
	                	   //Algo equivalent in webcrypto
	                	   algoTranslation: "AES-CBC",
	                	   kty: "oct",
	                	   use: "enc",
	                	   extract: true,
	                	   key: base64.stringifyUrlSafe(KEY128)
	                   },
	                   {
	                	   test: "ImportJWK_A256CBC",
	                	   algo: "A256CBC",
	                	   //Algo equivalent in webcrypto
	                	   algoTranslation: "AES-CBC",
	                	   kty: "oct",
	                	   use: "enc",
	                	   extract: true,
	                	   key: base64.stringifyUrlSafe(KEY256)
	                   },
	                   {
	                	   test: "ImportJWK_A128GCM",
	                	   algo: "A128GCM",
	                	   //Algo equivalent in webcrypto
	                	   algoTranslation: "AES-GCM",
	                	   kty: "oct",
	                	   use: "enc",
	                	   extract: true,
	                	   key: base64.stringifyUrlSafe(KEY128)
	                   },
	                   {
	                	   test: "ImportJWK_A256GCM",
	                	   algo: "A256GCM",
	                	   //Algo equivalent in webcrypto
	                	   algoTranslation: "AES-GCM",
	                	   kty: "oct",
	                	   use: "enc",
	                	   extract: true,
	                	   key: base64.stringifyUrlSafe(KEY256)
	                   },
	                   {
	                	   test: "ImportJWK_HS256",
	                	   algo: "HS256",
	                	   //Algo equivalent in webcrypto
	                	   algoTranslation: "HMAC",
	                	   algoParams: "SHA-256",
	                	   kty: "oct",
	                	   use: "sig",
	                	   extract: true,
	                	   key: base64.stringifyUrlSafe(KEY256)
	                   },
	                   {
	                	   test: "ImportJWK_HS384",
	                	   algo: "HS384",
	                	   //Algo equivalent in webcrypto
	                	   algoTranslation: "HMAC",
	                	   algoParams: "SHA-384",
	                	   kty: "oct",
	                	   use: "sig",
	                	   extract: true,
	                	   key: base64.stringifyUrlSafe(KEY384)
	                   },
	                   {
	                	   test: "ImportJWK_HS512",
	                	   algo: "HS512",
	                	   //Algo equivalent in webcrypto
	                	   algoTranslation: "HMAC",
	                	   algoParams: "SHA-512",
	                	   kty: "oct",
	                	   use: "sig",
	                	   extract: true,
	                	   key: base64.stringifyUrlSafe(KEY512)
	                   },
	                   {
	                	   test: "ImportJWK_RS256",
	                	   algo: "RS256",
	                	   //Algo equivalent in webcrypto
	                	   algoTranslation: "RSASSA-PKCS1-v1_5",
	                	   algoParams: "SHA-256",
	                	   kty: "RSA",
	                	   use: "sig",
	                	   extract: true,
	                	   modulus: base64.stringifyUrlSafe([0x08, 0x00]),
	                	   //fermatF4
	                	   exponent: base64.stringifyUrlSafe(FERMATF4)
	                   },
	                   {
	                	   test: "ImportJWK_RS384",
	                	   algo: "RS384",
	                	   //Algo equivalent in webcrypto
	                	   algoTranslation: "RSASSA-PKCS1-v1_5",
	                	   algoParams: "SHA-384",
	                	   kty: "RSA",
	                	   use: "sig",
	                	   extract: true,
	                	   modulus: base64.stringifyUrlSafe([0x08, 0x00]),
	                	   //fermatF4
	                	   exponent: base64.stringifyUrlSafe(FERMATF4)
	                   },
	                   {
	                	   test: "ImportJWK_RS512",
	                	   algo: "RS512",
	                	   //Algo equivalent in webcrypto
	                	   algoTranslation: "RSASSA-PKCS1-v1_5",
	                	   algoParams: "SHA-512",
	                	   kty: "RSA",
	                	   use: "sig",
	                	   extract: true,
	                	   modulus: base64.stringifyUrlSafe([0x08, 0x00]),
	                	   //fermatF4
	                	   exponent: base64.stringifyUrlSafe(FERMATF4)
	                   },
	                   {
	                	   test: "ImportJWK_RSA1_5",
	                	   algo: "RSA1_5",
	                	   //Algo equivalent in webcrypto
	                	   algoTranslation: "RSAES-PKCS1-v1_5",
	                	   kty: "RSA",
	                	   use: "enc",
	                	   extract: true,
	                	   modulus: base64.stringifyUrlSafe(base16.parse(
	                			   "a8b3b284af8eb50b387034a860f146c4919f318763cd6c55" +
	                			   "98c8ae4811a1e0abc4c7e0b082d693a5e7fced675cf46685" +
	                			   "12772c0cbc64a742c6c630f533c8cc72f62ae833c40bf258" +
	                			   "42e984bb78bdbf97c0107d55bdb662f5c4e0fab9845cb514" +
	                			   "8ef7392dd3aaff93ae1e6b667bb3d4247616d4f5ba10d4cf" +
	                			   "d226de88d39f16fb"
	                	   )),
	                	   exponent: base64.stringifyUrlSafe(base16.parse("010001"))
	                   },
	                   {
	                	   test: "ImportJWK_RSA-OAEP",
	                	   algo: "RSA-OAEP",
	                	   //Algo equivalent in webcrypto
	                	   algoTranslation: "RSA-OAEP",
	                	   kty: "RSA",
	                	   use: "enc",
	                	   extract: true,
	                	   modulus: base64.stringifyUrlSafe([0x04, 0x00]),
	                	   exponent: base64.stringifyUrlSafe(FERMATF4)
	                   },

	                   {
	                	   test: "ImportJWK_A128KW",
	                	   algo: "A128KW",
	                	   //Algo equivalent in webcrypto
	                	   algoTranslation: "AES-KW",
	                	   kty: "oct",
	                	   use: "wrap",
	                	   extract: true,
	                	   key: base64.stringifyUrlSafe(KEY128)
	                   },

	                   {
	                	   test: "ImportJWK_A256KW",
	                	   algo: "A256KW",
	                	   //Algo equivalent in webcrypto
	                	   algoTranslation: "AES-KW",
	                	   kty: "oct",
	                	   use: "wrap",
	                	   extract: true,
	                	   key: base64.stringifyUrlSafe(KEY256)
	                   },
	                   ];
	function wrapperForTest(OPINDEX) {
		it(LISTOFTESTS[OPINDEX].test, function () {
			INDEXVALUE = LISTOFTESTS[OPINDEX];

			var error = undefined,
			importedKey = undefined,
			exportedData = undefined;

			if(INDEXVALUE.kty == "RSA") {
				var jwk = latin1.parse(JSON.stringify({
					alg: INDEXVALUE.algo,
					kty: INDEXVALUE.kty,
					use: INDEXVALUE.use,
					extractable: INDEXVALUE.extract,
					n: INDEXVALUE.modulus,
					e: INDEXVALUE.exponent
				}));
			} else {
				var jwk = latin1.parse(JSON.stringify({
					alg: INDEXVALUE.algo,
					kty: INDEXVALUE.kty,
					use: INDEXVALUE.use,
					extractable: INDEXVALUE.extract,
					k: INDEXVALUE.key,
				}));
			}

			runs(function () {
				var op = nfCrypto.importKey("jwk", jwk, { name: "RSAES-PKCS1-v1_5" }, true);
				op.onerror = function (e) {
					error = "ERROR";
				};
				op.oncomplete = function (e) {
					importedKey = e.target.result;
				};
			})
			waitsFor(function () {
				return importedKey || error;
			});
			runs(function () {
				expect(error).toBeUndefined();
				expect(importedKey).toBeDefined();
				expect(importedKey.algorithm.name).toBe(INDEXVALUE.algoTranslation);
				if(INDEXVALUE.algoTranslation == "HMAC") {
					expect(importedKey.algorithm.params.hash.name).toBe(INDEXVALUE.algoParams);
				}

			});

			//Export
			runs(function () {
				error = undefined;
				var op = nfCrypto.exportKey("jwk", importedKey);
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
				expect(JSON.parse(latin1.stringify(exportedData))).toEqual(JSON.parse(latin1.stringify(jwk)));
			});
		});//it
	}//function wrapperForTest
	for(OPINDEX = 0; OPINDEX < LISTOFTESTS.length; OPINDEX++) {
		wrapperForTest(OPINDEX);
	}
});//describe("importexportjwk")

