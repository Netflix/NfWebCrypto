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

describe("SignRSA", function () {

	//Globals
	var DATA = hex2abv("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
	var LARGE_DATA = base64.parse("eyJtZXNzYWdlaWQiOjQ2MDQwODM3Niwibm9ucmVwbGF5YWJsZSI6ZmFsc2UsInJlbmV3YWJsZSI6dHJ1ZSwiY2FwYWJpbGl0aWVzIjp7ImNvbXByZXNzaW9uYWxnb3MiOlsiTFpXIl19LCJrZXlyZXF1ZXN0ZGF0YSI6W3sic2NoZW1lIjoiQVNZTU1FVFJJQ19XUkFQUEVEIiwia2V5ZGF0YSI6eyJrZXlwYWlyaWQiOiJyc2FLZXlwYWlySWQiLCJtZWNoYW5pc20iOiJSU0EiLCJwdWJsaWNrZXkiOiJUVWxIU2tGdlIwSkJUMWxYVXpZMk5ubEhjazU1U0Vkbk4yMHZaMlJuYjBKMVJGaHpLM0JOU1dWTGNVNVBkMlZKYW5selRYSjRTVTk0WjJ4TVMzRkVOa2xsV2pkd01VSmlVRVY0V0ZoS2EzTlpOR2RUVGtNM01FTmxRVUpFVVRkRmIzRmlXR1V3UkRsVVZFNU9MMHBOVW01SmNtVnVaWFU1TldOeE5ucGhNSGcxVjFkemEzWkxTRTh6Y21GVk9YZEZjQzlaUlZNM2JWVnphMmx5V2s1QkswWlVUVlJhT1RKalUxaDZXUzlyTUZFMlpHVTNRV2ROUWtGQlJUMD0ifX1dfQ==");
	var OPINDEX = 0;
	var INDEXVALUE = 0;

	var LISTOFTESTS = [
	    {
	       	test: "SignVerifyRSAHappyPath",
	        algo: {name: "RSASSA-PKCS1-v1_5", params: { hash: "SHA-256" }},
	        testData: DATA,
	        result: "pass"
	    },	
	    
	    {
	    	//There is no limit on size of data to sign/verify since it has SHA performed on it
	       	test: "SignVerifyRSALargeData",
	        algo: {name: "RSASSA-PKCS1-v1_5", params: { hash: "SHA-256" }},
	        testData: LARGE_DATA,
	        result: "pass"
	    },	
	    
	    {
	       	test: "SignRSAEmptyData",
	        algo: {name: "RSASSA-PKCS1-v1_5", params: { hash: "SHA-256" }},
	        testData: hex2abv(""),
	        sign: true
	    },	
	    
	    {
	       	test: "SignRSANullData",
	        algo: {name: "RSASSA-PKCS1-v1_5", params: { hash: "SHA-256" }},
	        testData: null,
	        sign: true
	    },	
	    
	    {
	       	test: "SignRSAInvalidAlgo",
	        algo: {name: "RSASSA", params: { hash: "SHA-256" }},
	        testData: DATA,
	        sign: false
	    },	
	    
	    {
	       	test: "SignRSAInvalidAlgoType",
	        algo: {name: "SHA-1", params: { hash: "SHA-256" }},
	        testData: DATA,
	        sign: false
	    },	
	    
	    {   //Error since signing is using RSASSA-PKCS1-v1_5 import key uses RSAES-PKCS1-v1_5
	    	test: "RSASignMismatchImportAlgo",
	        algo: {name: "RSASSA-PKCS1-v1_5", params: { hash: "SHA-256" }},
	        testData: DATA,
	        sign: false
	    },	
	    
	    {   //!!!!NOTE THIS TEST WILL NOT WORK WHEN REAL WEBCRYPTO COMES ALONG!!!!!!!
	       	test: "SignRSAInvalidSignKey",
	        //key manipulation happens just before sign
	        algo: {name: "RSASSA-PKCS1-v1_5", params: { hash: "SHA-256" }},
	        testData: DATA,
	        sign: false
	    },	
	    
	    {   //Fails since the generated key only supports verify
	       	test: "SignUsingKeyWithInvalidUsage",
	        algo: {name: "RSASSA-PKCS1-v1_5", params: { hash: "SHA-256" }},
	        testData: DATA,
	        sign: false
	    },	
	    
	];
	
	function wrapperForTest(OPINDEX) {	

		it(LISTOFTESTS[OPINDEX].test, function () {
			INDEXVALUE = LISTOFTESTS[OPINDEX];
			var error = undefined,
				signature = undefined,
				verified = undefined,
				pubKey = undefined,
				privKey = undefined;

			//First generate the keys before each test
			var fermatF4 = new Uint8Array([0x01, 0x00, 0x01]);
			var error;

			runs(function () {
				try {
					if (INDEXVALUE.test == "RSASignMismatchImportAlgo" ) {
						var genOp = nfCrypto.generateKey({
							name: "RSAES-PKCS1-v1_5",
							params: {
								//2048 bit RSA key can encrypt (n/8) - 11 bytes for PKCS
								//With given 2048 bit key it can encrypt 245 bytes
								modulusLength: 2048,
								publicExponent: fermatF4,
							},
						});
					} else if (INDEXVALUE.test == "SignUsingKeyWithInvalidUsage" ) {
						var genOp = nfCrypto.generateKey({
							name: "RSASSA-PKCS1-v1_5",
							params: {
								modulusLength: 512,
								publicExponent: fermatF4,
							} },
							false,
							["verify"]);
					} else {
						var genOp = nfCrypto.generateKey({
							name: "RSASSA-PKCS1-v1_5",
							params: {
								modulusLength: 512,
								publicExponent: fermatF4,
							},
							//TODO: Add specific tests to check default values and see that 
							//they hold true wrt C++
						});
					}
					genOp.onerror = function (e) {
						error = "ERROR :: " + e.target.result;
					};
					genOp.oncomplete = function (e) {
						pubKey = e.target.result.publicKey;
						privKey = e.target.result.privateKey;
					};
				} catch(e) {
					error = "ERROR";
				}
			});
			waitsFor(function () {
				return pubKey || privKey || error;
			});

			runs(function () {
				expect(error).toBeUndefined();
				//Doing checks on keys to validate Public Key structure
				if (INDEXVALUE.test == "RSASignMismatchImportAlgo" ) {
					expect(pubKey.algorithm.name).toEqual("RSAES-PKCS1-v1_5");
				} else {
					expect(pubKey.algorithm.name).toEqual("RSASSA-PKCS1-v1_5");
				}
				//Even though default value is extractable: false public keys are always extractable
				expect(pubKey.extractable).toBeTruthy();
				if (INDEXVALUE.test == "SignUsingKeyWithInvalidUsage" ) {
					expect(pubKey.keyUsage.length).toEqual(1);
				} else {
					expect(pubKey.keyUsage.length).toEqual(0);
				}
				//TODO: Re-enable this check when we know what default values should be
				//expect(pubKey.keyUsage[0]).toEqual("verify");
				expect(pubKey.keyUsage).not.toBeNull();
				expect(pubKey.type).toEqual("public");
				//Handle is how C++ correlates keys with JS
				//0 implies invalid key
				expect(pubKey.handle).not.toEqual(0);

				//Doing checks on keys to validate Private Key structure
				if (INDEXVALUE.test == "RSASignMismatchImportAlgo" ) {
					expect(privKey.algorithm.name).toEqual("RSAES-PKCS1-v1_5");
				} else {
					expect(privKey.algorithm.name).toEqual("RSASSA-PKCS1-v1_5");
				}
				expect(privKey.extractable).toBeFalsy();
				if (INDEXVALUE.test == "SignUsingKeyWithInvalidUsage" ) {
					expect(privKey.keyUsage.length).toEqual(1);
				} else {
					expect(privKey.keyUsage.length).toEqual(0);
				}
				//TODO: Re-enable this check when we know what default values should be
				//expect(privKey.keyUsage[0]).toEqual("sign");
				expect(privKey.type).toEqual("private");
				expect(privKey.handle).not.toEqual(0);
				expect(privKey.handle).not.toEqual(pubKey.handle);
			});

			// sign data with the private key
			runs(function () {
				try {
					error = undefined;
					//Invalidating the handle for specific test case
					if (INDEXVALUE.test == "SignRSAInvalidSignKey" ) {
						privKey.handle = 0;
					} 
					var signOp = nfCrypto.sign(INDEXVALUE.algo, privKey, INDEXVALUE.testData);
					signOp.onerror = function (e) {
						error = "ERROR :: " + e.target.result;
					};
					signOp.oncomplete = function (e) {
						signature = e.target.result;
					};
				} catch(e) {
					error = "ERROR";
				}
			});

			waitsFor(function () {
				return signature || error;
			});

			runs(function () {
				if (INDEXVALUE.sign == false) {
					expect(error).toBeDefined();
					expect(signature).toBeUndefined();
				} else {
					expect(error).toBeUndefined();
					expect(signature).toBeDefined();
				}
			});
          
			if (INDEXVALUE.sign == false) {
				// verify data with the public key
				runs(function () {
					try {
						error = undefined;
						var verifyOp = nfCrypto.verify(INDEXVALUE.algo, pubKey, signature, INDEXVALUE.testData);
						verifyOp.onerror = function (e) {
							error = "ERROR :: " + e.target.result;
						};
						verifyOp.oncomplete = function (e) {
							verified = e.target.result;
						};
					} catch(e) {
						error = "ERROR";
					}
				});

				waitsFor(function () {
					return verified || error;
				});

				runs(function () {
	                if (INDEXVALUE.sign == false) {
	                    expect(error).toBeDefined();
	                    expect(signature).toBeUndefined();
	                } else {
	                    expect(error).toBeUndefined();
	                    expect(signature).toBeDefined();
	                }
				});
			}//if (INDEXVALUE.sign == false) 
		});//it
	}//function wrapperForTest
	for(OPINDEX = 0; OPINDEX < LISTOFTESTS.length; OPINDEX++) {	
		wrapperForTest(OPINDEX);
	}
});//describe("SignRSA")		

describe("VerifyRSA", function () {

	//Globals
	var DATA = hex2abv("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
	var SIGN_ALGO = {name: "RSASSA-PKCS1-v1_5", params: { hash: "SHA-256" }};
	var OPINDEX = 0;
	var INDEXVALUE = 0;

	var LISTOFTESTS = [
	    
	    {
	       	test: "VerifyRSAEmptyData",
	        algo: {name: "RSASSA-PKCS1-v1_5", params: { hash: "SHA-256" }},
	        testData: hex2abv(""),
	        verify: false
	    },	
	    
	    {
	       	test: "VerifyRSANullData",
	        algo: {name: "RSASSA-PKCS1-v1_5", params: { hash: "SHA-256" }},
	        testData: null,
	        verify: false
	    },	
	    
	    {
	       	test: "VerifyRSAInvalidAlgo",
	        algo: {name: "PKCS1-v1_5", params: { hash: "SHA-256" }},
	        testData: DATA,
	        verify: false
	    },	
	    
	    {
	       	test: "VerifyRSAInvalidAlgoType",
	        algo: {name: "SHA-384", params: { hash: "SHA-256" }},
	        testData: DATA,
	        verify: false
	    },	
	    
	    {   //!!!!NOTE THIS TEST WILL NOT WORK WHEN REAL WEBCRYPTO COMES ALONG!!!!!!!
	       	test: "VerifyRSAInvalidVerifyKey",
	        //key manipulation happens just before verify
	        algo: {name: "RSASSA-PKCS1-v1_5", params: { hash: "SHA-256" }},
	        testData: DATA,
	        verify: false
	    },	
	    
	    {   //Invalidation of signature occurs below
	       	test: "VerifyRSAInvalidSignature",
	        algo: {name: "RSASSA-PKCS1-v1_5", params: { hash: "SHA-256" }},
	        testData: DATA,
	        verify: false
	    },	
	    
	    {   //Fails since the generated key only supports sign
	       	test: "VerifyUsingKeyWithInvalidUsage",
	        algo: {name: "RSASSA-PKCS1-v1_5", params: { hash: "SHA-256" }},
	        testData: hex2abv(""),
	        verify: false
	    },	
	];
	
	function wrapperForTest(OPINDEX) {	

		it(LISTOFTESTS[OPINDEX].test, function () {
			INDEXVALUE = LISTOFTESTS[OPINDEX];
			var error = undefined,
				signature = undefined,
				verified = undefined,
				pubKey = undefined,
				privKey = undefined;

			//First generate the keys before each test
			var fermatF4 = new Uint8Array([0x01, 0x00, 0x01]);
			var error;

			runs(function () {
				try {
					var genOp = undefined;
					if (INDEXVALUE.test == "VerifyUsingKeyWithInvalidUsage" ) {
						genOp = nfCrypto.generateKey({
						name: "RSASSA-PKCS1-v1_5",
						params: {
							modulusLength: 512,
							publicExponent: fermatF4,
						} },
						false,
						["sign"]);
					} else {
						genOp = nfCrypto.generateKey({
							name: "RSASSA-PKCS1-v1_5",
							params: {
								modulusLength: 512,
								publicExponent: fermatF4,
							},
						});
					}
					genOp.onerror = function (e) {
						error = "ERROR :: " + e.target.result;
					};
					genOp.oncomplete = function (e) {
						pubKey = e.target.result.publicKey;
						privKey = e.target.result.privateKey;
					};
				} catch(e) {
					error = "ERROR";
				}
			});
			waitsFor(function () {
				return pubKey || privKey || error;
			});

			runs(function () {
				expect(error).toBeUndefined();
				//Doing checks on keys to validate Public Key structure
				expect(pubKey.algorithm.name).toEqual("RSASSA-PKCS1-v1_5");
				//Even thoug default value is extractable: false public keys are always extractable
				expect(pubKey.extractable).toBeTruthy();
				if (INDEXVALUE.test == "VerifyUsingKeyWithInvalidUsage" ) {
					expect(pubKey.keyUsage.length).toEqual(1);
				} else {
					expect(pubKey.keyUsage.length).toEqual(0);
				}
				//TODO: Re-enable this check when we know what default values should be
				//expect(pubKey.keyUsage[0]).toEqual("verify");
				expect(pubKey.keyUsage).not.toBeNull();
				expect(pubKey.type).toEqual("public");
				//Handle is how C++ correlates keys with JS
				//0 implies invalid key
				expect(pubKey.handle).not.toEqual(0);

				//Doing checks on keys to validate Private Key structure
				expect(privKey.algorithm.name).toEqual("RSASSA-PKCS1-v1_5");
				expect(privKey.extractable).toBeFalsy();
				if (INDEXVALUE.test == "VerifyUsingKeyWithInvalidUsage" ) {
					expect(privKey.keyUsage.length).toEqual(1);
				} else {
					expect(privKey.keyUsage.length).toEqual(0);
				}
				//TODO: Re-enable this check when we know what default values should be
				//expect(privKey.keyUsage[0]).toEqual("sign");
				expect(privKey.type).toEqual("private");
				expect(privKey.handle).not.toEqual(0);
				expect(privKey.handle).not.toEqual(pubKey.handle);
			});

			// sign data with the private key
			runs(function () {
				try {
					error = undefined;
					var signOp = nfCrypto.sign(SIGN_ALGO, privKey, DATA);
					signOp.onerror = function (e) {
						error = "ERROR :: " + e.target.result;
					};
					signOp.oncomplete = function (e) {
						signature = e.target.result;
					};
				} catch(e) {
					error = "ERROR";
				}
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
				try {
					error = undefined;
					//Invalidating the handle for specific test case
					if (INDEXVALUE.test == "VerifyRSAInvalidVerifyKey") {
						pubKey.handle = 0;
					} else if (INDEXVALUE.test == "VerifyRSAInvalidSignature") {
						signature[5] = signature[5] ^ 0xFF;
					} 
					var verifyOp = nfCrypto.verify(INDEXVALUE.algo, pubKey, signature, INDEXVALUE.testData);
					verifyOp.onerror = function (e) {
						error = "ERROR :: " + e.target.result;
					};
					verifyOp.oncomplete = function (e) {
						verified = e.target.result;
					};
				} catch(e) {
					error = "ERROR";
				}					
			});

			waitsFor(function () {
				return (typeof verified !== 'undefined') || error;
			});

			runs(function () {
				if (INDEXVALUE.verify == false) {
				    if (INDEXVALUE.test == "VerifyRSAInvalidSignature" ||
	                    INDEXVALUE.test == "VerifyRSAEmptyData"        ||
                        INDEXVALUE.test == "VerifyRSANullData"           )
				    {
	                    expect(error).toBeUndefined();
	                    expect(verified).toBe(false);
				    } else {
				        expect(error).toBeDefined();
				        expect(verified).toBeUndefined();
				    }
				} else {
					expect(error).toBeUndefined();
					expect(verified).toBe(true);
				}
			});

		});//it
	}//function wrapperForTest
	for(OPINDEX = 0; OPINDEX < LISTOFTESTS.length; OPINDEX++) {	
		wrapperForTest(OPINDEX);
	}
});//describe("VerifyRSA")	