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

describe("SignHMAC", function () {

	//Globals
	var DATA = hex2abv("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
	var OPINDEX = 0;
	var INDEXVALUE = 0;

	var LISTOFTESTS = [
	    {
	       	test: "SignVerifyHappyPath",
	        algo: { name: "HMAC", params: { hash: "SHA-256" }},
	        testData: DATA,
	        result: "pass"
	    },	
	    
	    {
	       	test: "SignEmptyData",
	        algo: { name: "HMAC", params: { hash: "SHA-256" }},
	        testData: hex2abv(""),
	        sign: false
	    },
	    
	    {
	       	test: "SignNullData",
	        algo: { name: "HMAC", params: { hash: "SHA-256" }},
	        testData: null,
	        sign: false
	    },
	    
	    {
	       	test: "SignInvalidAlgo",
	        algo: { name: "hmac", params: { hash: "SHA-256" }},
	        testData: DATA,
	        sign: false
	    },	
	    
	    {
	       	test: "SignInvalidAlgoType",
	        algo: { name: "SHA-1", params: { hash: "SHA-256" }},
	        testData: DATA,
	        sign: false
	    },	
	    
	    {   //Error since signing is using HMAC import key is using AES-CBC
	       	test: "SignAlgoMismatchImportAlgo",
	        algo: { name: "HMAC", params: { hash: "SHA-256" }},
	        testData: DATA,
	        sign: false
	    },	
	    
	    {
	    	//!!!!NOTE THIS TEST WILL NOT WORK WHEN REAL WEBCRYPTO COMES ALONG!!!!!!!
	       	test: "SignInvalidSignKey",
	       	//key manipulation happens just before import
	        algo: { name: "HMAC", params: { hash: "SHA-256" }},
	        testData: DATA,
	        sign: false
	    },	
	    
	    {   //Fails since import key only supports verify
	       	test: "SignUsingKeyWithInvalidUsage",
	        algo: { name: "HMAC", params: { hash: "SHA-256" }},
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
			    importKey = undefined;
			
			var keyData = new Uint8Array([
			                          0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
			                          0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
			                          ]);
            //First import the key to sign/verify with
			runs(function () {
				try {
					error = undefined;
					var op = undefined;
					if (INDEXVALUE.test == "SignAlgoMismatchImportAlgo") {
						op = nfCrypto.importKey("raw", keyData, { name: "AES-CBC", params: { hash: "SHA-256" } }, true);
					} else if (INDEXVALUE.test == "SignUsingKeyWithInvalidUsage") {
						op = nfCrypto.importKey("raw", keyData, { name: "HMAC", params: { hash: "SHA-256" } }, true, ["verify"]);
					} else {
						op = nfCrypto.importKey("raw", keyData, { name: "HMAC", params: { hash: "SHA-256" } }, true, ["sign", "verify"]);
					}
					op.onerror = function (e) {
						error = "ERROR";
					};
					op.oncomplete = function (e) {
						importKey = e.target.result;
					};
				} catch(e) {
					error = "ERROR";
				}
			});

			waitsFor(function () {
				return importKey || error;
			});

			runs(function () {
				expect(error).toBeUndefined();
				expect(importKey).toBeDefined();
			});
			
			runs(function () {
				try {
					error = undefined;
					//Making a bad sign key
					if (INDEXVALUE.test == "SignInvalidSignKey" ) {
						importKey.handle = 0;
						INDEXVALUE.testKey = importKey;
					} else {
						//initalized testKey value with importkey
						INDEXVALUE.testKey = importKey;
					}
					var signOp = nfCrypto.sign(INDEXVALUE.algo, INDEXVALUE.testKey, INDEXVALUE.testData);
					signOp.onerror = function (e) {
						error = "ERROR";
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

			if (INDEXVALUE.sign != false) {
				runs(function () {
					try {
						error = undefined;
						//initalized testKey value with importkey
						//INDEXVALUE.testKey = importKey;
						var signOp = nfCrypto.verify(INDEXVALUE.algo, INDEXVALUE.testKey, signature, INDEXVALUE.testData);
						signOp.onerror = function (e) {
							error = "ERROR";
						};
						signOp.oncomplete = function (e) {
							verified = e.target.result;
						};
					} catch(e) {
						error = "ERROR";
					}					
				});

				waitsFor(function () {
					return verified !== undefined || error;
				});

				runs(function () {
					expect(error).toBeUndefined();
					expect(verified).toBe(true);
				});
			}//if (INDEXVALUE.sign == false)
		});//it
	}//function wrapperForTest
	for(OPINDEX = 0; OPINDEX < LISTOFTESTS.length; OPINDEX++) {	
		wrapperForTest(OPINDEX);
	}
});//describe("SignHMAC")

describe("VerifyHMAC", function () {

	//Globals
	var GOOD_DATA = hex2abv("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
	var SIGN_ALGO = { name: "HMAC", params: { hash: "SHA-256" }};
	var OPINDEX = 0;
	var INDEXVALUE = 0;

	var LISTOFTESTS = [
	     //Sign should pass and all the verifies should fail              
	    {
	       	test: "VerifyEmptyData",
	        algo: { name: "HMAC", params: { hash: "SHA-256" }},
	        testData: hex2abv(""),
	        verify: false
	    },
	    
	    {
	       	test: "VerifyNullData",
	        algo: { name: "HMAC", params: { hash: "SHA-256" }},
	        testData: null,
	        verify: false
	    },
	    
	    {
	       	test: "VerifyInvalidAlgo",
	        algo: { name: "hmac", params: { hash: "SHA-256" }},
	        testData: GOOD_DATA,
	        verify: false
	    },	
	    
	    {
	       	test: "VerifyInvalidAlgoType",
	        algo: { name: "SHA-1", params: { hash: "SHA-256" }},
	        testData: GOOD_DATA,
	        verify: false
	    },
	    
	    {   //!!!!NOTE THIS TEST WILL NOT WORK WHEN REAL WEBCRYPTO COMES ALONG!!!!!!!
	       	test: "VerifyInvalidKey",
	        //key manipulation happens just before verify
	        algo: { name: "HMAC", params: { hash: "SHA-256" }},
	        testData: GOOD_DATA,
	        verify: false
	    },
	    
	    {   //Invalidation of signature occurs below
	       	test: "VerifyInvalidSignature",
	        algo: { name: "HMAC", params: { hash: "SHA-256" }},
	        testData: GOOD_DATA,
	        verify: false
	    },
	    
	    {   //Fails since imported key only supports sign usage
	       	test: "VerifyUsingKeyWithInvalidUsage",
	        algo: { name: "HMAC", params: { hash: "SHA-256" }},
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
			    importKey = undefined;
			
			var keyData = new Uint8Array([
			                          0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
			                          0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
			                          ]);
            //First import the key to sign/verify with
			runs(function () {
				try {
					error = undefined;
					var op = undefined;
					if (INDEXVALUE.test == "VerifyUsingKeyWithInvalidUsage" ) {
						op = nfCrypto.importKey("raw", keyData, { name: "HMAC", params: { hash: "SHA-256" } }, true, ["sign"]);
					} else {
						op = nfCrypto.importKey("raw", keyData, { name: "HMAC", params: { hash: "SHA-256" } }, true, ["sign", "verify"]);
					} 
					op.onerror = function (e) {
						error = "ERROR";
					};
					op.oncomplete = function (e) {
						importKey = e.target.result;
					};
				} catch(e) {
					error = "ERROR";
				}
			});

			waitsFor(function () {
				return importKey || error;
			});

			runs(function () {
				expect(error).toBeUndefined();
				expect(importKey).toBeDefined();
			});
			
			runs(function () {
				try {
					error = undefined;
					INDEXVALUE.testKey = importKey;
					
			    	var signOp = nfCrypto.sign(SIGN_ALGO, importKey, GOOD_DATA);
					signOp.onerror = function (e) {
						error = "ERROR";
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

			runs(function () {
				try {
					error = undefined;
					if (INDEXVALUE.test == "VerifyInvalidKey") {
						INDEXVALUE.testKey.handle = 0;
					} else if (INDEXVALUE.test == "VerifyInvalidSignature") {
						//flipping bits 
						signature[5] = signature[5] ^ 0xFF;
					}
					var signOp = nfCrypto.verify(INDEXVALUE.algo, INDEXVALUE.testKey, signature, INDEXVALUE.testData);
					signOp.onerror = function (e) {
						error = "ERROR";
					};
					signOp.oncomplete = function (e) {
						verified = e.target.result;
					};
				} catch(e) {
					error = "ERROR";
				}
			});

			waitsFor(function () {
				return verified !== undefined || error;
			});

			runs(function () {
				if (INDEXVALUE.verify == false) {
					//Error is returned in the verify object indicating false
				    if (INDEXVALUE.test == "VerifyInvalidSignature") {
	                    expect(error).toBeUndefined();
	                    expect(verified).toBe(false);
				    }
				    else {
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
});//describe("VerifyHMAC")


