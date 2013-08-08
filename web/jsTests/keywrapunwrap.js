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

describe("keywrapunwraprsa", function () {

	var LISTOFOPERATIONS = [
	    {
	    	name: "WrapUnwrapRSA_OAEPHappyPath",
	    	wrapAlgo: { name: "RSA-OAEP" },
	    	unwrapAlgo: null, 
	    	unwrapExtractable: true,
	        result: "pass"
	    },
	    
	    {
	    	//Input to wrap is AES-KW which is different the wrappor algo
	    	//which will cause failure
	    	name: "WrapAlgoDiffFromWrapporAlgo",
	    	wrapAlgo: { name: "AES-KW" },
	    	unwrapAlgo: null, 
	    	disableUnwrap: true,
			wrap: false
	    },
	     
	    {
	    	//Expect to fail since this is not a supported wrap algo
		    name: "IncorrectWrapAlgo",
		    wrapAlgo: { name: "SHA-1" },
		    unwrapAlgo: null, 
		    disableUnwrap: true,
			wrap: false
		},
		
		{
			//Expected to pass since JWEData input to unwrap has correct algo 
	    	name: "IncorrectUnwrapAlgo",
	    	wrapAlgo: { name: "RSA-OAEP" },
	    	unwrapAlgo: { name: "SHA-384" },
	    	unwrapExtractable: true,
	    	result: "pass"
	    },
	    
	    {
	    	//Expect wrap to fail since this algo PKCS1-v1_5 does not exist
		    name: "InvalidWrapAlgo",
		    wrapAlgo: { name: "PKCS1-v1_5" },
		    unwrapAlgo: null, 
		    disableUnwrap: true,
			wrap: false
		},
		
		{
			//Expected to fail since this algo PKCS1-v1_5 does not exist
	    	name: "InvalidUnwrapAlgo",
	    	wrapAlgo: { name: "RSA-OAEP" },
	    	unwrapAlgo: { name: "PKCS1-v1_5" }, 
	    	unwrap: false
	    },
	    
	    {   //Wrap/unwrap will pass export will fail
	    	name: "UnwrapExtractableFalse",
	    	wrapAlgo: { name: "RSA-OAEP" },
	    	unwrapAlgo: null, 
	    	unwrapExtractable: false,
	        result: "pass"
	    },
	    
	    {   //Specifying empty string as the algo for the wrappee key
	    	//Wrapee key params are ignored only key handle is referenced hence no error
	    	name: "WrapeeKeyIncorrectAlgo",
	    	wrapAlgo: { name: "RSA-OAEP" },
	    	unwrapAlgo: null, 
	    	unwrapExtractable: true,
	        result: "pass"
	    },
	    
	    {   //Invalidating key handle
	    	//!!!!!!!!!!!!!!NOTE TEST WILL NOT WORK WITH REAL WEBCRYPTO !!!!!!!!//
	    	name: "WrapeeKeyInvalidHandle",
	    	wrapAlgo: { name: "RSA-OAEP" },
	    	unwrapAlgo: null, 
		    disableUnwrap: true,
		    wrap: false
	    },
	    
	    {   //Specifying empty string as the algo for the wrappor key
	    	//Wrapor key params are ignored only key handle is referenced hence no error
	    	name: "WrapporKeyIncorrectAlgo",
	    	wrapAlgo: { name: "RSA-OAEP" },
	    	unwrapAlgo: null, 
	    	unwrapExtractable: true,
	        result: "pass"
	    },
	    
	    {   //Invalidating key handle
	    	//!!!!!!!!!!!!!!NOTE TEST WILL NOT WORK WITH REAL WEBCRYPTO !!!!!!!!//
	    	name: "WrapporKeyInvalidHandle",
	    	wrapAlgo: { name: "RSA-OAEP" },
	    	unwrapAlgo: null, 
		    disableUnwrap: true,
		    wrap: false
	    },
	    
	    {   //Specifying empty string as the algo for the wrappor key
	    	//Wrapor key params are ignored only key handle is referenced hence no error
	    	name: "UnwrapWrapporKeyIncorrectAlgo",
	    	wrapAlgo: { name: "RSA-OAEP" },
	    	unwrapAlgo: null, 
	    	unwrapExtractable: true,
	        result: "pass"
	    },
	    
	    {   //Invalidating key handle
	    	//!!!!!!!!!!!!!!NOTE TEST WILL NOT WORK WITH REAL WEBCRYPTO !!!!!!!!//
	    	name: "UnwrapWrapporKeyInvalidHandle",
	    	wrapAlgo: { name: "RSA-OAEP" },
	    	unwrapAlgo: null, 
		    unwrap: false,
	    },
	    
	    {   //Mangling data between wrap and unwrap expect failure
	    	name: "MangledWrapData",
	    	wrapAlgo: { name: "RSA-OAEP" },
	    	unwrapAlgo: null, 
		    unwrap: false
	    },
	    
	    {   //Wrap missing algo input
	    	name: "WrapMissingAlgoInput",
	    	wrapAlgo: { name: "RSA-OAEP" },
	    	unwrapAlgo: null, 
	    	unwrapExtractable: true,
	        result: "pass"
	    },
	    
	    {   //Wrap/unwrap will pass export will fail
	    	name: "WrapeeExtractableFalseUnwrapExtractableTrue",
	    	wrapAlgo: { name: "RSA-OAEP" },
	    	unwrapAlgo: null, 
	    	unwrapExtractable: true,
	        result: "pass"
	    },
	    
	    {   //Unwrap algo is ignored since jwe algo is looked at
	    	name: "WrapUnwrapAlgoMisMatch",
	    	wrapAlgo: { name: "RSA-OAEP" },
	    	unwrapAlgo: { name: "AES-KW" }, 
	    	unwrapExtractable: true,
	        result: "pass"
	    },
	    
	    {   //Between wrap/unwrap change the encrypted key to a short value
	    	name: "WrapShortKeyUnwrap",
	    	wrapAlgo: { name: "RSA-OAEP" },
	    	unwrapAlgo: null, 
	    	unwrapExtractable: true,
	        unwrap: false
	    },
	    
	    {   //Fails since the wrapping key usage is only for unwrap
	    	name: "WrapUsingKeyWithIvalidUsage",
	    	wrapAlgo: { name: "RSA-OAEP" },
	    	unwrapAlgo: null, 
	    	disableUnwrap: true,
			wrap: false
	    },
	    
	];
	var OPINDEX = 0;
	var INDEXVALUE = 0;
	//For wrap/unwrap 1. Generate the wrapping keys(wrappor)
	//2. Generate the wrapee key
	//3. Wrap/unwrap the keys
	//The algos supported for wrapping/generating keys are RSA-OAEP, AES-KW
	//Algos supported for wrapee key are: any symmetric key(AES, HMAC), asymmetric public key RSA, DH
	function wrapperForTest(OPINDEX) {	
		it(LISTOFOPERATIONS[OPINDEX].name, function () {
			INDEXVALUE = LISTOFOPERATIONS[OPINDEX];
			
			var error = undefined,
				keyToWrap = undefined,
				keyData = new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F]),
				unwrappedKey = undefined,
				exportKeyData = undefined,
				jweData = undefined,
				pubKey = undefined,
				privKey = undefined;

			// generate RSA pub/priv key pair for wrapping with
			runs(function () {
				try {
					var genOp = undefined;
					if(INDEXVALUE.name == "WrapUsingKeyWithIvalidUsage") {
						genOp = nfCrypto.generateKey({name: "RSA-OAEP", params: { modulusLength: 1024, publicExponent: new Uint8Array([0x01, 0x00, 0x01])}},
								false,
								["unwrap"]
						);
					} else {
						genOp = nfCrypto.generateKey({name: "RSA-OAEP", params: { modulusLength: 1024, publicExponent: new Uint8Array([0x01, 0x00, 0x01])}},
								false,
								["wrap", "unwrap"]
						);
					}
					genOp.onerror = function (e) {
						error = "ERROR";
					};
					genOp.oncomplete = function (e) {
						pubKey  = e.target.result.publicKey;
						privKey = e.target.result.privateKey;
					};
				} catch(e) {
					error = "ERROR";
				}
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
				try {
					error = undefined;
					var op = undefined;
					if(INDEXVALUE.name == "WrapeeExtractableFalseUnwrapExtractableTrue") {
						op = nfCrypto.importKey("raw", keyData, { name: "AES-CBC" }, false);
					} else {
						op = nfCrypto.importKey("raw", keyData, { name: "AES-CBC" }, true);
					}
					op.onerror = function (e) {
						error = "ERROR";
					};
					op.oncomplete = function (e) {
						keyToWrap = e.target.result;
					};
				} catch(e) {
					error = "ERROR";
				}
			});
			waitsFor(function () {
				return keyToWrap || error;
			});
			runs(function () {
				expect(error).toBeUndefined();
				expect(keyToWrap).toBeDefined();
			});

			// wrap the wrap-ee key using the public wrapping key
			runs(function () {
				try {
					error = undefined;
					var op = undefined;
					if(INDEXVALUE.name == "WrapeeKeyIncorrectAlgo") {
						keyToWrap.algorithm.name = "";
					} else if (INDEXVALUE.name == "WrapeeKeyInvalidHandle") {
						keyToWrap.handle = 0;
					} else if (INDEXVALUE.name == "WrapporKeyIncorrectAlgo") {
						pubKey.algorithm.name = "";
					} else if (INDEXVALUE.name == "WrapporKeyInvalidHandle") {
						pubKey.handle = 0;
					}

					if (INDEXVALUE.name == "WrapMissingAlgoInput") {
						//Did not specify wrap algo
						op = nfCrypto.wrapKey(keyToWrap, pubKey);
					} else {
						op = nfCrypto.wrapKey(keyToWrap, pubKey, INDEXVALUE.wrapAlgo);
					}


					op.onerror = function (e) {
						error = "ERROR";
					};
					op.oncomplete = function (e) {
						jweData = e.target.result;
					};
				} catch(e) {
					error = "ERROR";
				}
			});
			waitsFor(function () {
				return jweData || error;
			});
			runs(function () {
				if(INDEXVALUE.wrap == false) {
					expect(error).toBeDefined();
					expect(jweData).toBeUndefined();
				} else {
					expect(error).toBeUndefined();
					expect(jweData).toBeDefined();
				}
			});

			if(INDEXVALUE.disableUnwrap != true) {
				// now unwrap the jwe data received from wrapKey, using the private wrapping key
				// this gives us a new key in the key store
				runs(function () {
					try {
						error = undefined;
						var op = undefined;
						if(INDEXVALUE.name == "MangledWrapData") {
							jweData[5] = jweData[5] ^ 0xFF;
						} else if (INDEXVALUE.name == "UnwrapWrapporKeyInvalidAlgo") {
							privKey.algorithm.name = "";
						} else if (INDEXVALUE.name == "UnwrapWrapporKeyInvalidHandle") {
							privKey.handle = 0;
						} 

						if(INDEXVALUE.name == "WrapShortKeyUnwrap") {
							//"short key" test: replace the encrypted CMK with "x"
							var jwe = latin1.stringify(jweData);
							var jweObj = JSON.parse(jwe);
							jweObj.recipients[0].encrypted_key = base64.stringifyUrlSafe([0x78]);
							var newJwe = JSON.stringify(jweObj);
							op = nfCrypto.unwrapKey(latin1.parse(newJwe), INDEXVALUE.unwrapAlgo, privKey, INDEXVALUE.unwrapExtractable);    
						} else {
							op = nfCrypto.unwrapKey(jweData, INDEXVALUE.unwrapAlgo, privKey, INDEXVALUE.unwrapExtractable);
						}

						op.onerror = function (e) {
							error = "ERROR";
						};
						op.oncomplete = function (e) {
							unwrappedKey = e.target.result;
						};
					} catch(e) {
						error = "ERROR";
					}
				});
				waitsFor(function () {
					return unwrappedKey || error;
				});
				runs(function () {
					if (INDEXVALUE.unwrap == false) {
						expect(error).toBeDefined();
						expect(unwrappedKey).toBeUndefined();
					} else {
						expect(error).toBeUndefined();
						expect(unwrappedKey).toBeDefined();
						expect(algorithmName(unwrappedKey.algorithm)).toBe("AES-CBC");
						expect(unwrappedKey.type).toBe("secret");
						if(INDEXVALUE.name == "WrapeeExtractableFalseUnwrapExtractableTrue") {
							expect(unwrappedKey.extractable).toBeFalsy;
						} else {
							expect(unwrappedKey.extractable).toEqual(INDEXVALUE.unwrapExtractable);
						}	
						//expect(unwrappedKey.usages.length).toEqual(0)
					}
				});

				// finally, export this new key and verify the raw key data
				runs(function () {
					try {
						error = undefined;
						var op = nfCrypto.exportKey("raw", unwrappedKey);
						op.onerror = function (e) {
							error = "ERROR";
						};
						op.oncomplete = function (e) {
							exportKeyData = e.target.result;
						};
					} catch(e) {
						error = "ERROR";
					}
				});
				waitsFor(function () {
					return exportKeyData || error;
				});
				runs(function () {
					if(INDEXVALUE.name == "UnwrapExtractableFalse" || INDEXVALUE.unwrap == false || INDEXVALUE.name == "WrapeeExtractableFalseUnwrapExtractableTrue") {
						expect(error).toBeDefined();
						expect(exportKeyData).toBeUndefined();
					} else {
						expect(error).toBeUndefined();
						expect(exportKeyData).toBeDefined();
						expect(base16.stringify(exportKeyData)).toEqual(base16.stringify(keyData));
					}	
				});
			}//if(INDEXVALUE.disableUnwrap)
	});//it
}//function wrapperForTest
for(OPINDEX = 0; OPINDEX < LISTOFOPERATIONS.length; OPINDEX++) {	
	wrapperForTest(OPINDEX);
}
});//describe("keywrapunwraprsa")

describe("keywrapunwrapaes", function () {


	var LISTOFOPERATIONS = [
	    {
	    	name: "WrapUnwrapAES_KWHappyPath",
	    	wrapAlgo: { name: "AES-KW" },
	    	unwrapAlgo: null, 
	    	unwrapExtractable: true,
	        result: "pass"
	    },
	    
	    {
	    	//Input to wrap is RSA-OAEP which is different the wrappor algo
	    	//which will cause failure
	    	name: "AESWrapAlgoDiffFromWrapporAlgo",
	    	wrapAlgo: { name: "RSA-OAEP" },
	    	unwrapAlgo: null, 
	    	disableUnwrap: true,
			wrap: false
	    },
	    
	    {
	    	//Expect to fail since SHA-384 isn't a correct wrap algo
		    name: "AESIncorrectWrapAlgo",
		    wrapAlgo: { name: "SHA-384" },
		    unwrapAlgo: null, 
		    disableUnwrap: true,
			wrap: false
		},
		
		{
			//Expected to pass since JWEData input to unwrap has correct algo 
	    	name: "AESIncorrectUnwrapAlgo",
	    	wrapAlgo: { name: "AES-KW" },
	    	unwrapAlgo: { name: "SHA-384" }, 
	    	unwrapExtractable: true,
	    	result: "pass"
	    },
	    
	    {
	    	//Expect to fail since there is no RSAES algo 
		    name: "AESInvalidWrapAlgo",
		    wrapAlgo: { name: "RSAES" },
		    unwrapAlgo: null, 
			disableUnwrap: true,
			wrap: false
		},
		
		{
			//Expect to fail since there is no RSAES algo 
	    	name: "AESInvaldiUnwrapAlgo",
	    	wrapAlgo: { name: "AES-KW" },
	    	unwrapAlgo: { name: "RSAES" }, 
	    	unwrapExtractable: true,
	    	unwrap: false
	    },
	    
	    {   //Wrap/unwrap will pass export will fail
	    	name: "AESUnwrapExtractableFalse",
	    	wrapAlgo: { name: "AES-KW" },
	    	unwrapAlgo: null, 
	    	unwrapExtractable: false,
	        result: "pass"
	    },
	    
	    {   //Specifying empty string as the algo for the wrappee key
	    	//Wrapee key params are ignored only key handle is referenced
	    	name: "AESWrapeeKeyIncorrectAlgo",
	    	wrapAlgo: { name: "AES-KW" },
	    	unwrapAlgo: null, 
	    	unwrapExtractable: true,
	    	result: "pass"
	    },
	    
	    {   //Invalidating key handle
	    	//!!!!!!!!!!!!!!NOTE TEST WILL NOT WORK WITH REAL WEBCRYPTO !!!!!!!!//
	    	name: "AESWrapeeKeyInvalidHandle",
	    	wrapAlgo: { name: "AES-KW" },
	    	unwrapAlgo: null, 
		    disableUnwrap: true,
		    wrap: false
	    },
	    
	    {   //Specifying empty string as the algo for the wrappee key
	    	//Wrapor key params are ignored only key handle is referenced
	    	name: "AESWrapporKeyIncorrectAlgo",
	    	wrapAlgo: { name: "AES-KW" },
	    	unwrapAlgo: null, 
	    	unwrapExtractable: true,
	        result: "pass"
	    },
	    
	    {   //Invalidating key handle
	    	//!!!!!!!!!!!!!!NOTE TEST WILL NOT WORK WITH REAL WEBCRYPTO !!!!!!!!//
	    	name: "AESWrapporKeyInvalidHandle",
	    	wrapAlgo: { name: "AES-KW" },
	    	unwrapAlgo: null, 
		    disableUnwrap: true,
		    wrap: false
	    },
	    
	    {   //Specifying empty string as the algo for the wrappor key
	    	//Wrapor key params are ignored only key handle is referenced hence no error
	    	name: "AESUnwrapWrapporKeyIncorrectAlgo",
	    	wrapAlgo: { name: "AES-KW" },
	    	unwrapAlgo: null, 
	    	unwrapExtractable: true,
	        result: "pass"
	    },
	    
	    {   //Invalidating key handle
	    	//!!!!!!!!!!!!!!NOTE TEST WILL NOT WORK WITH REAL WEBCRYPTO !!!!!!!!//
	    	name: "AESUnwrapWrapporKeyInvalidHandle",
	    	wrapAlgo: { name: "AES-KW" },
	    	unwrapAlgo: null, 
		    unwrap: false,
	    },
	    
	    {   //Mangling data between wrap and unwrap expect failure
	    	name: "AESMangledWrapData",
	    	wrapAlgo: { name: "AES-KW" },
	    	unwrapAlgo: null, 
		    unwrap: false
	    },
	    
	    {   //Wrap missing algo input
	    	name: "AESWrapMissingAlgoInput",
	    	wrapAlgo: { name: "AES-KW" },
	    	unwrapAlgo: null, 
	    	unwrapExtractable: true,
	        result: "pass"
	    },
	    
	    {   //Unwrap algo is ignored since jwe algo is looked at
	    	name: "AESWrapUnwrapAlgoMisMatch",
	    	wrapAlgo: { name: "AES-KW" },
	    	unwrapAlgo: { name: "RSA-OAEP" }, 
	    	unwrapExtractable: true,
	        result: "pass"
	    },
	    
	    {   //Unwrap algo is ignored since jwe algo is looked at
	    	name: "AESWrapShortKeyUnwrap",
	    	wrapAlgo: { name: "AES-KW" },
	    	unwrapAlgo: { name: "RSA-OAEP" }, 
	    	unwrapExtractable: true,
	        unwrap: false
	    },
	    
	    {   //Fails since the wrapping key usage is only for unwrap
	    	name: "AESWrapUsingKeyWithInvalidUsage",
	    	wrapAlgo: { name: "AES-KW" },
	    	unwrapAlgo: null, 
	    	disableUnwrap: true,
			wrap: false
	    },
    ];
	var OPINDEX = 0;
	var INDEXVALUE = 0;
	//For wrap/unwrap 1. Generate the wrapping keys(wrappor)
	//2. Generate the wrapee key
	//3. Wrap/unwrap the keys
	//The algos supported for wrapping/generating keys are RSA-OAEP, AES-KW
	//Algos supported for wrapee key are: any symmetric key(AES, HMAC), asymmetric public key RSA, DH
	function wrapperForTest(OPINDEX) {	
		it(LISTOFOPERATIONS[OPINDEX].name, function () {
			INDEXVALUE = LISTOFOPERATIONS[OPINDEX];
				
		    var error,
             	 wrapeeKey,
             	 wrapeeKeyData,
             	 wrapporKey,
             	 wrappedKeyJwe,
             	 unwrappedWrappeeKey,
             	 unwrappedWrappeeKeyData;
         
			
			// generate a key to be wrapped
            runs(function () {
            	try {
            		error = undefined;
            		var op = nfCrypto.generateKey({ name: "HMAC", params: { hash: {name: "SHA-256"} } }, true);

            		op.onerror = function (e) {
            			error = "ERROR";
            		};
            		op.oncomplete = function (e) {
            			wrapeeKey = e.target.result;
            		};
            	} catch(e) {
            		error = "ERROR";
            	}
            });
            waitsFor(function () {
                return wrapeeKey || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(wrapeeKey).toBeDefined();
            });
            
            // export the wrap-ee key data for later checking only if extractable is set to true
            runs(function () {
            	try {
            		error = undefined;
            		var op = nfCrypto.exportKey("raw", wrapeeKey);
            		op.onerror = function (e) {
            			error = "ERROR";
            		};
            		op.oncomplete = function (e) {
            			wrapeeKeyData = e.target.result;
            		};
            	} catch(e) {
            		error = "ERROR";
            	}
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
            	try {
            		error = undefined;
            		var op = undefined;
            		if(INDEXVALUE.name == "AESWrapUsingKeyWithInvalidUsage") {
            			op = nfCrypto.generateKey({ name: "AES-KW", params: { length: 128 } }, false, ["unwrap"]);
            		} else {
            			op = nfCrypto.generateKey({ name: "AES-KW", params: { length: 128 } });
            		}

            		op.onerror = function (e) {
            			error = "ERROR";
            		};
            		op.oncomplete = function (e) {
            			wrapporKey = e.target.result;
            		};
            	} catch(e) {
            		error = "ERROR";
            	}
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
            	try {
            		error = undefined;
            		var op = undefined;
            		if(INDEXVALUE.name == "AESWrapeeKeyIncorrectAlgo") {
            			wrapeeKey.algorithm.name = "";
            		} else if (INDEXVALUE.name == "AESWrapeeKeyInvalidHandle") {
            			wrapeeKey.handle = 0;
            		} else if (INDEXVALUE.name == "AESWrapporKeyIncorrectAlgo") {
            			wrapporKey.algorithm.name = "";
            		} else if (INDEXVALUE.name == "AESWrapporKeyInvalidHandle") {
            			wrapporKey.handle = 0;
            		} 

            		if (INDEXVALUE.name == "AESWrapMissingAlgoInput") {
            			//Did not specify wrap algo
            			op = nfCrypto.wrapKey(wrapeeKey, wrapporKey);
            		} else {
            			op = nfCrypto.wrapKey(wrapeeKey, wrapporKey, INDEXVALUE.wrapAlgo);
            		}

            		op.onerror = function (e) {
            			error = "ERROR";
            		};
            		op.oncomplete = function (e) {
            			wrappedKeyJwe = e.target.result;
            		};
            	} catch(e) {
            		error = "ERROR";
            	}
            });
            waitsFor(function () {
                return wrappedKeyJwe || error;
            });
            runs(function () {
            	if(INDEXVALUE.wrap == false){
            		expect(error).toBeDefined();
                    expect(wrappedKeyJwe).toBeUndefined();
            	} else {
            		expect(error).toBeUndefined();
                    expect(wrappedKeyJwe).toBeDefined();
            	}
            });
            
            if(INDEXVALUE.disableUnwrap != true) {
            	// unwrap the resulting JWE
            	runs(function () {
            		try {
            			error = undefined;
            			var op = undefined;
            			if(INDEXVALUE.name == "AESMangledWrapData") {
            				wrappedKeyJwe[5] = wrappedKeyJwe[5] ^ 0xFF;
            			} else if (INDEXVALUE.name == "AESUnwrapWrapporKeyInvalidAlgo") {
            				wrapporKey.algorithm.name = "";
            			} else if (INDEXVALUE.name == "AESUnwrapWrapporKeyInvalidHandle") {
            				wrapporKey.handle = 0;
            			} 

            			if(INDEXVALUE.name == "AESWrapShortKeyUnwrap") {
            				//"short key" test: replace the encrypted CMK with "x"
            				var jwe = latin1.stringify(wrappedKeyJwe);
            				var jweObj = JSON.parse(jwe);
            				jweObj.recipients[0].encrypted_key = base64.stringifyUrlSafe([0x78]);
            				var newJwe = JSON.stringify(jweObj);
            				op = nfCrypto.unwrapKey(latin1.parse(newJwe), INDEXVALUE.unwrapAlgo, wrapporKey, INDEXVALUE.unwrapExtractable);    
            			} else {
            				op = nfCrypto.unwrapKey(wrappedKeyJwe, INDEXVALUE.unwrapAlgo, wrapporKey, INDEXVALUE.unwrapExtractable);
            			}

            			op.onerror = function (e) {
            				error = "ERROR";
            			};
            			op.oncomplete = function (e) {
            				unwrappedWrappeeKey = e.target.result;
            			};
            		} catch(e) {
            			error = "ERROR";
            		}
            	});
            	waitsFor(function () {
                	return unwrappedWrappeeKey || error;
            	});
            	runs(function () {
            		if(INDEXVALUE.unwrap == false) {
            			expect(error).toBeDefined();
                		expect(unwrappedWrappeeKey).toBeUndefined();
            		} else {
            			expect(error).toBeUndefined();
                		expect(unwrappedWrappeeKey).toBeDefined();
                		expect(algorithmName(unwrappedWrappeeKey.algorithm)).toBe("HMAC");
            		}
            	});
            
            	// export the raw key and compare to the original
            	runs(function () {
            		try {
            			error = undefined;
            			var op = nfCrypto.exportKey("raw", unwrappedWrappeeKey);
            			op.onerror = function (e) {
            				error = "ERROR";
            			};
            			op.oncomplete = function (e) {
            				unwrappedWrappeeKeyData = e.target.result;
            			};
            		} catch(e) {
            			error = "ERROR";
            		}
            	});
            	waitsFor(function () {
            		return unwrappedWrappeeKeyData || error;
            	});
            	runs(function () {
            		if(INDEXVALUE.name == "AESUnwrapExtractableFalse" || INDEXVALUE.unwrap == false) {
						expect(error).toBeDefined();
						expect(unwrappedWrappeeKeyData).toBeUndefined();
					} else {
						expect(error).toBeUndefined();
						expect(unwrappedWrappeeKeyData).toBeDefined();
						expect(base16.stringify(unwrappedWrappeeKeyData)).toEqual(base16.stringify(wrapeeKeyData));
					}
            	});
			}//if(INDEXVALUE.disableUnwrap)
	});//it
}//function wrapperForTest
for(OPINDEX = 0; OPINDEX < LISTOFOPERATIONS.length; OPINDEX++) {	
	wrapperForTest(OPINDEX);
}
});//describe("keywrapunwrapaes")

describe("keywrapunwrapjwejsrsa-oaep", function () {

	var LISTOFOPERATIONS = [
	    //All the test will fail unwrap since the jwe-js obj is mangled
	    {
	       name: "RemoveJWEJSRecipients",
	       wrapAlgo: { name: "RSA-OAEP" },
	       unwrapAlgo: null, 
	       unwrapExtractable: true,
	    },
	                       
	    {
	    	name: "RemoveJWEJSHeader",
	    	wrapAlgo: { name: "RSA-OAEP" },
	    	unwrapAlgo: null, 
	    	unwrapExtractable: true,
	    },
	    
	    {
	    	name: "RemoveJWEJSEncryptedKey",
	    	wrapAlgo: { name: "RSA-OAEP" },
	    	unwrapAlgo: null, 
	    	unwrapExtractable: true,
	    },
	    
	    {
	    	name: "RemoveJWEJSIntegrityValue",
	    	wrapAlgo: { name: "RSA-OAEP" },
	    	unwrapAlgo: null, 
	    	unwrapExtractable: true,
	    },
	   
	    {
	    	name: "RemoveJWEJSInitializationVector",
	    	wrapAlgo: { name: "RSA-OAEP" },
	    	unwrapAlgo: null, 
	    	unwrapExtractable: true,
	    },
	    
	    {
	    	name: "RemoveJWEJSCipherText",
	    	wrapAlgo: { name: "RSA-OAEP" },
	    	unwrapAlgo: null, 
	    	unwrapExtractable: true,
	    },
	    
	    {
	       name: "InvalidJWEJSRecipients",
	       wrapAlgo: { name: "RSA-OAEP" },
	       unwrapAlgo: null, 
	       unwrapExtractable: true,
	    },
	    
	    {
	    	name: "InvalidJWEJSHeader",
	    	wrapAlgo: { name: "RSA-OAEP" },
	    	unwrapAlgo: null, 
	    	unwrapExtractable: true,
	    },
	    
	    {
	    	name: "InvalidJWEJSEncryptedKey",
	    	wrapAlgo: { name: "RSA-OAEP" },
	    	unwrapAlgo: null, 
	    	unwrapExtractable: true,
	    },
	    
	    {
	    	name: "InvalidJWEJSIntegrityValue",
	    	wrapAlgo: { name: "RSA-OAEP" },
	    	unwrapAlgo: null, 
	    	unwrapExtractable: true,
	    },
	   
	    {
	    	name: "InvalidJWEJSInitializationVector",
	    	wrapAlgo: { name: "RSA-OAEP" },
	    	unwrapAlgo: null, 
	    	unwrapExtractable: true,
	    },
	    
	    {
	    	name: "InvalidJWEJSCipherText",
	    	wrapAlgo: { name: "RSA-OAEP" },
	    	unwrapAlgo: null, 
	    	unwrapExtractable: true,
	    },
	    
	    {
		    name: "InvalidSerialization",
		    wrapAlgo: { name: "RSA-OAEP" },
		    unwrapAlgo: null, 
		    unwrapExtractable: true,
		},
		
		{
		    name: "WrongJWEJSIntegrityValue",
		    wrapAlgo: { name: "RSA-OAEP" },
		    unwrapAlgo: null, 
		    unwrapExtractable: true,
		},
		
		{
		    name: "WrongJWEJSEncryptedKey",
		    wrapAlgo: { name: "RSA-OAEP" },
		    unwrapAlgo: null, 
		    unwrapExtractable: true,
		},
		
		{
		    name: "WrongJWEJSInitializationVector",
		    wrapAlgo: { name: "RSA-OAEP" },
		    unwrapAlgo: null, 
		    unwrapExtractable: true,
		},
		
		{   //Invalidating the algo param within the header
		    name: "HeaderInvalidAlgo",
		    wrapAlgo: { name: "RSA-OAEP" },
		    unwrapAlgo: null, 
		    unwrapExtractable: true,
		},
		
		{   //Removing the algo param within the header
		    name: "HeaderMissingAlgo",
		    wrapAlgo: { name: "RSA-OAEP" },
		    unwrapAlgo: null, 
		    unwrapExtractable: true,
		},
		
		{   //Invalidating the encryption param within the header
		    name: "HeaderInvalidEnc",
		    wrapAlgo: { name: "RSA-OAEP" },
		    unwrapAlgo: null, 
		    unwrapExtractable: true,
		},
		
		{   //Removing the encryption param within the header
		    name: "HeaderMissingEnc",
		    wrapAlgo: { name: "RSA-OAEP" },
		    unwrapAlgo: null, 
		    unwrapExtractable: true,
		},
	    
	];
	
	var OPINDEX = 0;
	var INDEXVALUE = 0;
	//For wrap/unwrap 1. Generate the wrapping keys(wrappor)
	//2. Generate the wrapee key
	//3. Wrap/unwrap the keys
	//The algos supported for wrapping/generating keys are RSA-OAEP, AES-KW
	//Algos supported for wrapee key are: any symmetric key(AES, HMAC), asymmetric public key RSA, DH
	function wrapperForTest(OPINDEX) {	
		it(LISTOFOPERATIONS[OPINDEX].name, function () {
			INDEXVALUE = LISTOFOPERATIONS[OPINDEX];
			
			var error = undefined,
				keyToWrap = undefined,
				keyData = new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F]),
				unwrappedKey = undefined,
				exportKeyData = undefined,
				jweData = undefined,
				pubKey = undefined,
				privKey = undefined;
			
			function randomBytes(buffer) {
				for (var i = 0; i < buffer.length; ++i)
	                buffer[i] = Math.floor(Math.random() * (0xFF - 0 + 1)) + 0;
			}
			
			// generate RSA pub/priv key pair for wrapping with
			runs(function () {
				try {
					var genOp = nfCrypto.generateKey({name: "RSA-OAEP", params: { modulusLength: 1024, publicExponent: new Uint8Array([0x01, 0x00, 0x01])}},
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
				} catch(e) {
					error = "ERROR";
				}
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
				try {
					error = undefined;
					var op = undefined;
					op = nfCrypto.importKey("raw", keyData, { name: "AES-CBC" }, true);

					op.onerror = function (e) {
						error = "ERROR";
					};
					op.oncomplete = function (e) {
						keyToWrap = e.target.result;
					};
				} catch(e) {
					error = "ERROR";
				}
			});
			waitsFor(function () {
				return keyToWrap || error;
			});
			runs(function () {
				expect(error).toBeUndefined();
				expect(keyToWrap).toBeDefined();
			});

			// wrap the wrap-ee key using the public wrapping key
			runs(function () {
				try {
					error = undefined;
					var op = undefined;
					op = nfCrypto.wrapKey(keyToWrap, pubKey, INDEXVALUE.wrapAlgo);

					op.onerror = function (e) {
						error = "ERROR";
					};
					op.oncomplete = function (e) {
						jweData = e.target.result;
					};
				} catch(e) {
					error = "ERROR";
				}
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
				var op = undefined;
				
				var jwe = latin1.stringify(jweData);
		        var jweObj = JSON.parse(jwe);
		        var recipient = jweObj.recipients[0];
				var testName = INDEXVALUE.name;
				var recipientFlag = false;
		       
		        switch (testName) {
		        	case "RemoveJWEJSRecipients":
		        		// Return immediately after removing because this creates a
		        		// malformed serialization.
		        		delete jweObj.recipients;
		        		break;
		        	case "RemoveJWEJSHeader":
		        		delete recipient["header"];
		        		recipientFlag = true;
		        		break;
		        	case "RemoveJWEJSEncryptedKey":
		        		delete recipient["encrypted_key"];
		        		recipientFlag = true;
		        		break;
		        	case "RemoveJWEJSIntegrityValue":
		        		delete recipient["integrity_value"];
		        		recipientFlag = true;
		        		break;
		        	case "RemoveJWEJSInitializationVector":
		        		delete jweObj.initialization_vector;
		        		break;
		        	case "RemoveJWEJSCipherText":
		        		delete jweObj.ciphertext;
		        		break;
		        	case "InvalidJWEJSRecipients":
		        		// Return immediately after removing because this creates a
		        		// malformed serialization.
		        		jweObj.recipients = ["x"];
		        		break;
		        	case "InvalidJWEJSHeader":
		        		recipient["header"] = b64urlEncode("x");
		        		recipientFlag = true;
		        		break;
		        	case "InvalidJWEJSEncryptedKey":
		        		recipient["encrypted_key"] = b64urlEncode("x");
		        		recipientFlag = true;
		        		break;
		        	case "InvalidJWEJSIntegrityValue":
		        		recipient["integrity_value"] = b64urlEncode("x");
		        		recipientFlag = true;
		        		break;
		        	case "InvalidJWEJSInitializationVector":
		        		jweObj.initialization_vector = b64urlEncode("x");
		        		break;
		        	case "InvalidJWEJSCipherText":
		        		jweObj.ciphertext = b64urlEncode("x");
		        		break;
		        	case "WrongJWEJSIntegrityValue":
		        		var at = new Uint8Array(16);
		                randomBytes(at);
		        		jweObj.ciphertext = b64urlEncode(at);
		        		break;
		        	case "WrongJWEJSEncryptedKey":
		        		 var ecek = new Uint8Array(137);
		                 randomBytes(ecek);
		        		jweObj.ciphertext = b64urlEncode(ecek);
		        		break;
		        	case "WrongJWEJSInitializationVector":
		        		 var iv = new Uint8Array(31);
		                 randomBytes(iv);
		        		jweObj.ciphertext = b64urlEncode(iv);
		        		break;
		        	case "HeaderInvalidAlgo":
		        		var headerB64 = recipient["header"];
		                var header = JSON.parse(textEncoding$getString(b64urlDecode(headerB64), "utf-8"));
		                header["alg"] = "x";
		                recipient["header"] = textEncoding$getString(header, "utf-8");
		                recipientFlag = true;
		        		break;
		        	case "HeaderMissingAlgo":
		        		var headerB64 = recipient["header"];
		                var header = JSON.parse(textEncoding$getString(b64urlDecode(headerB64), "utf-8"));
		                delete header["alg"];
			            recipient["header"] = textEncoding$getString(header, "utf-8");
			            recipientFlag = true;
		        		break;
		        	case "HeaderInvalidEnc":
		        		var headerB64 = recipient["header"];
		                var header = JSON.parse(textEncoding$getString(b64urlDecode(headerB64), "utf-8"));
		                header["enc"] = "x";
		                recipient["header"] = textEncoding$getString(header, "utf-8");
		                recipientFlag = true;
		        		break;
		        	case "HeaderMissingEnc":
		        		var headerB64 = recipient["header"];
		                var header = JSON.parse(textEncoding$getString(b64urlDecode(headerB64), "utf-8"));
		                delete header["enc"];
			            recipient["header"] = textEncoding$getString(header, "utf-8");
			            recipientFlag = true;
		                break;
		        	default:
		        		//Do nothing since there are tests that will not follow this model
		        }
		        if (recipientFlag == true) {
		           	jweObj.recipients[0] = recipient;
		        	recipientFlag = false;
		        } 
		        try {
		        	if (INDEXVALUE.name == "InvalidSerialization") {
		        		jweData =  textEncoding$getString("x", "utf-8");
		        		op = nfCrypto.unwrapKey(latin1.parse(jweData), INDEXVALUE.unwrapAlgo, privKey, INDEXVALUE.unwrapExtractable);    
		        	} else {
		        		var newJwe = JSON.stringify(jweObj);
		        		op = nfCrypto.unwrapKey(latin1.parse(newJwe), INDEXVALUE.unwrapAlgo, privKey, INDEXVALUE.unwrapExtractable);    
		        	}

		        	op.onerror = function (e) {
		        		error = "ERROR";
		        	};
		        	op.oncomplete = function (e) {
		        		unwrappedKey = e.target.result;
		        	};
		        } catch(e) {
		        	error = "ERROR";
		        }
			});
			waitsFor(function () {
				return unwrappedKey || error;
			});
			runs(function () {
				expect(error).toBeDefined();
				expect(unwrappedKey).toBeUndefined();
			});

			// finally, export this new key and verify the raw key data
			runs(function () {
				try {
					error = undefined;
					var op = nfCrypto.exportKey("raw", unwrappedKey);
					op.onerror = function (e) {
						error = "ERROR";
					};
					op.oncomplete = function (e) {
						exportKeyData = e.target.result;
					};
				} catch(e) {
					error = "ERROR";
				}
			});
			waitsFor(function () {
				return exportKeyData || error;
			});
			runs(function () {
				expect(error).toBeDefined();
				expect(exportKeyData).toBeUndefined(); 
			});
	});//it
}//function wrapperForTest
for(OPINDEX = 0; OPINDEX < LISTOFOPERATIONS.length; OPINDEX++) {	
	wrapperForTest(OPINDEX);
}
});//describe("keywrapunwrapjwejsrsa-oaep")

describe("keywrapunwrapjwejsaes", function () {


	var LISTOFOPERATIONS = [
	    	    
	    //All the test will fail unwrap since the jwe-js obj is mangled
	    {
	       name: "AESRemoveJWEJSRecipients",
	       wrapAlgo: { name: "AES-KW" },
	       unwrapAlgo: null, 
	       unwrapExtractable: true,
	    },
	                       
	    {
	    	name: "AESRemoveJWEJSHeader",
	    	wrapAlgo: { name: "AES-KW" },
	    	unwrapAlgo: null, 
	    	unwrapExtractable: true,
	    },
	    
	    {
	    	name: "AESRemoveJWEJSEncryptedKey",
	    	wrapAlgo: { name: "AES-KW" },
	    	unwrapAlgo: null, 
	    	unwrapExtractable: true,
	    },
	    
	    {
	    	name: "AESRemoveJWEJSIntegrityValue",
	    	wrapAlgo: { name: "AES-KW" },
	    	unwrapAlgo: null, 
	    	unwrapExtractable: true,
	    },
	   
	    {
	    	name: "AESRemoveJWEJSInitializationVector",
	    	wrapAlgo: { name: "AES-KW" },
	    	unwrapAlgo: null, 
	    	unwrapExtractable: true,
	    },
	    
	    {
	    	name: "AESRemoveJWEJSCipherText",
	    	wrapAlgo: { name: "AES-KW" },
	    	unwrapAlgo: null, 
	    	unwrapExtractable: true,
	    },
	    
	    {
	       name: "AESInvalidJWEJSRecipients",
	       wrapAlgo: { name: "AES-KW" },
	       unwrapAlgo: null, 
	       unwrapExtractable: true,
	    },
	    
	    {
	    	name: "AESInvalidJWEJSHeader",
	    	wrapAlgo: { name: "AES-KW" },
	    	unwrapAlgo: null, 
	    	unwrapExtractable: true,
	    },
	    
	    {
	    	name: "AESInvalidJWEJSEncryptedKey",
	    	wrapAlgo: { name: "AES-KW" },
	    	unwrapAlgo: null, 
	    	unwrapExtractable: true,
	    },
	    
	    {
	    	name: "AESInvalidJWEJSIntegrityValue",
	    	wrapAlgo: { name: "AES-KW" },
	    	unwrapAlgo: null, 
	    	unwrapExtractable: true,
	    },
	   
	    {
	    	name: "AESInvalidJWEJSInitializationVector",
	    	wrapAlgo: { name: "AES-KW" },
	    	unwrapAlgo: null, 
	    	unwrapExtractable: true,
	    },
	    
	    {
	    	name: "AESInvalidJWEJSCipherText",
	    	wrapAlgo: { name: "AES-KW" },
	    	unwrapAlgo: null, 
	    	unwrapExtractable: true,
	    },
	    
	    {
		    name: "AESInvalidSerialization",
		    wrapAlgo: { name: "AES-KW" },
		    unwrapAlgo: null, 
		    unwrapExtractable: true,
		},
		
		{
		    name: "AESWrongJWEJSIntegrityValue",
		    wrapAlgo: { name: "AES-KW" },
		    unwrapAlgo: null, 
		    unwrapExtractable: true,
		},
		
		{
		    name: "AESWrongJWEJSEncryptedKey",
		    wrapAlgo: { name: "AES-KW" },
		    unwrapAlgo: null, 
		    unwrapExtractable: true,
		},
		
		{
		    name: "AESWrongJWEJSInitializationVector",
		    wrapAlgo: { name: "AES-KW" },
		    unwrapAlgo: null, 
		    unwrapExtractable: true,
		},
		
		{   //Invalidating the algo param within the header
		    name: "AESHeaderInvalidAlgo",
		    wrapAlgo: { name: "AES-KW" },
		    unwrapAlgo: null, 
		    unwrapExtractable: true,
		},
		
		{   //Removing the algo param within the header
		    name: "AESHeaderMissingAlgo",
		    wrapAlgo: { name: "AES-KW" },
		    unwrapAlgo: null, 
		    unwrapExtractable: true,
		},
		
		{   //Invalidating the encryption param within the header
		    name: "AESHeaderInvalidEnc",
		    wrapAlgo: { name: "AES-KW" },
		    unwrapAlgo: null, 
		    unwrapExtractable: true,
		},
		
		{   //Removing the encryption param within the header
		    name: "AESHeaderMissingEnc",
		    wrapAlgo: { name: "AES-KW" },
		    unwrapAlgo: null, 
		    unwrapExtractable: true,
		}
	    
	    
	    ];
	var OPINDEX = 0;
	var INDEXVALUE = 0;
	//For wrap/unwrap 1. Generate the wrapping keys(wrappor)
	//2. Generate the wrapee key
	//3. Wrap/unwrap the keys
	//The algos supported for wrapping/generating keys are RSA-OAEP, AES-KW
	//Algos supported for wrapee key are: any symmetric key(AES, HMAC), asymmetric public key RSA, DH
	function wrapperForTest(OPINDEX) {	
		it(LISTOFOPERATIONS[OPINDEX].name, function () {
			INDEXVALUE = LISTOFOPERATIONS[OPINDEX];
				
		    var error,
             	 wrapeeKey,
             	 wrapeeKeyData,
             	 wrapporKey,
             	 wrappedKeyJwe,
             	 unwrappedWrappeeKey,
             	 unwrappedWrappeeKeyData;
		    
		    function randomBytes(buffer) {
				for (var i = 0; i < buffer.length; ++i)
	                buffer[i] = Math.floor(Math.random() * (0xFF - 0 + 1)) + 0;
			}
         			
			// generate a key to be wrapped
            runs(function () {
            	try {
            		error = undefined;
            		var op = nfCrypto.generateKey({ name: "HMAC", params: { hash: {name: "SHA-256"} } }, true);

            		op.onerror = function (e) {
            			error = "ERROR";
            		};
            		op.oncomplete = function (e) {
            			wrapeeKey = e.target.result;
            		};
            	} catch(e) {
            		error = "ERROR";
            	}
            });
            waitsFor(function () {
                return wrapeeKey || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(wrapeeKey).toBeDefined();
            });
            
            // export the wrap-ee key data for later checking only if extractable is set to true
            runs(function () {
            	try {
            		error = undefined;
            		var op = nfCrypto.exportKey("raw", wrapeeKey);
            		op.onerror = function (e) {
            			error = "ERROR";
            		};
            		op.oncomplete = function (e) {
            			wrapeeKeyData = e.target.result;
            		};
            	} catch(e) {
            		error = "ERROR";
            	}
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
            	try {
            		error = undefined;
            		var op = nfCrypto.generateKey({ name: "AES-KW", params: { length: 128 } });
            		op.onerror = function (e) {
            			error = "ERROR";
            		};
            		op.oncomplete = function (e) {
            			wrapporKey = e.target.result;
            		};
            	} catch(e) {
            		error = "ERROR";
            	}
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
            	try {
            		error = undefined;
            		var op = undefined;

            		op = nfCrypto.wrapKey(wrapeeKey, wrapporKey, INDEXVALUE.wrapAlgo);

            		op.onerror = function (e) {
            			error = "ERROR";
            		};
            		op.oncomplete = function (e) {
            			wrappedKeyJwe = e.target.result;
            		};
            	} catch(e) {
            		error = "ERROR";
            	}
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
            	var op = undefined;
            	var recipientFlag = false;
            	
            	var jwe = latin1.stringify(wrappedKeyJwe);
		        var jweObj = JSON.parse(jwe);
		        var recipient = jweObj.recipients[0];
				var testName = INDEXVALUE.name;
		       
		        switch (testName) {
		        	case "AESRemoveJWEJSRecipients":
		        		// Return immediately after removing because this creates a
		        		// malformed serialization.
		        		delete jweObj.recipients;
		        		break;
		        	case "AESRemoveJWEJSHeader":
		        		delete recipient["header"];
		        		recipientFlag = true;
		        		break;
		        	case "AESRemoveJWEJSEncryptedKey":
		        		delete recipient["encrypted_key"];
		        		recipientFlag = true;
		        		break;
		        	case "AESRemoveJWEJSIntegrityValue":
		        		delete recipient["integrity_value"];
		        		recipientFlag = true;
		        		break;
		        	case "AESRemoveJWEJSInitializationVector":
		        		delete jweObj.initialization_vector;
		        		break;
		        	case "AESRemoveJWEJSCipherText":
		        		delete jweObj.ciphertext;
		        		break;
		        	case "AESInvalidJWEJSRecipients":
		        		// Return immediately after removing because this creates a
		        		// malformed serialization.
		        		jweObj.recipients = ["x"];
		        		break;
		        	case "AESInvalidJWEJSHeader":
		        		recipient["header"] = b64urlEncode("x");
		        		recipientFlag = true;
		        		break;
		        	case "AESInvalidJWEJSEncryptedKey":
		        		recipient["encrypted_key"] = b64urlEncode("x");
		        		recipientFlag = true;
		        		break;
		        	case "AESInvalidJWEJSIntegrityValue":
		        		recipient["integrity_value"] = b64urlEncode("x");
		        		recipientFlag = true;
		        		break;
		        	case "AESInvalidJWEJSInitializationVector":
		        		jweObj.initialization_vector = b64urlEncode("x");
		        		break;
		        	case "AESInvalidJWEJSCipherText":
		        		jweObj.ciphertext = b64urlEncode("x");
		        		break;
		        	case "AESWrongJWEJSIntegrityValue":
		        		var at = new Uint8Array(16);
		                randomBytes(at);
		        		jweObj.ciphertext = b64urlEncode(at);
		        		break;
		        	case "AESWrongJWEJSEncryptedKey":
		        		var ecek = new Uint8Array(137);
		                randomBytes(ecek);
		        		jweObj.ciphertext = b64urlEncode(ecek);
		        		break;
		        	case "AESWrongJWEJSInitializationVector":
		        		var iv = new Uint8Array(31);
		                randomBytes(iv);
		        		jweObj.ciphertext = b64urlEncode(iv);
		        		break;
		        	case "AESHeaderInvalidAlgo":
		        		var headerB64 = recipient["header"];
		                var header = JSON.parse(textEncoding$getString(b64urlDecode(headerB64, "utf-8")));
		        		header["alg"] = "x";
		                //recipient["header"] = textEncoding$getString(header, "utf-8");
		                recipient["header"] = utf8.parse(header);
		                recipientFlag = true;
		        		break;
		        	case "AESHeaderMissingAlgo":
		        		var headerB64 = recipient["header"];
		                var header = JSON.parse(textEncoding$getString(b64urlDecode(headerB64, "utf-8")));
		                delete header["alg"];
		                recipient["header"] = utf8.parse(header);
		                recipientFlag = true;
		        		break;
		        	case "AESHeaderInvalidEnc":
		        		var headerB64 = recipient["header"];
		                var header = JSON.parse(textEncoding$getString(b64urlDecode(headerB64, "utf-8")));
		                header["enc"] = "x";
		                recipient["header"] = utf8.parse(header);
		                recipientFlag = true;
		        		break;
		        	case "AESHeaderMissingEnc":
		        		var headerB64 = recipient["header"];
		                var header = JSON.parse(textEncoding$getString(b64urlDecode(headerB64, "utf-8")));
		                delete header["enc"];
		                recipient["header"] = utf8.parse(header);
		                recipientFlag = true;
		                break;
		        	default:
		        		//Do nothing since there are tests that will not follow this model
		        }
		        if (recipientFlag == true) {
		        	jweObj.recipients[0] = recipient;
		        	recipientFlag = false;
		        } 
		        try {
		        	if (INDEXVALUE.name == "AESInvalidSerialization") {
		        		wrappedKeyJwe = utf8.parse("x");
		        		op = nfCrypto.unwrapKey(wrappedKeyJwe, INDEXVALUE.unwrapAlgo, wrapporKey, INDEXVALUE.unwrapExtractable);
		        	} else {
		        		var newJwe = JSON.stringify(jweObj);
		        		op = nfCrypto.unwrapKey(latin1.parse(newJwe), INDEXVALUE.unwrapAlgo, wrapporKey, INDEXVALUE.unwrapExtractable);    
		        	}          	

		        	op.onerror = function (e) {
		        		error = "ERROR";
		        	};
		        	op.oncomplete = function (e) {
		        		unwrappedWrappeeKey = e.target.result;
		        	};
		        } catch(e) {
		        	error = "ERROR";
		        }
            });
            waitsFor(function () {
               	return unwrappedWrappeeKey || error;
            });
            runs(function () {
            	expect(error).toBeDefined();
               	expect(unwrappedWrappeeKey).toBeUndefined();
            });
	});//it
}//function wrapperForTest
for(OPINDEX = 0; OPINDEX < LISTOFOPERATIONS.length; OPINDEX++) {	
	wrapperForTest(OPINDEX);
}
});//describe("keywrapunwrapjwejsaes")
