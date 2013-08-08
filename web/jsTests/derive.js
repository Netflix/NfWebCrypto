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

describe("derive", function () {

	var dhPrime = base64.parse(
            "lpTp2Nk6WsdMUJtLvOhekhMs0ZzOR30afkfVJ9nsKRUV8Liz4ertUAbh" +
            "sbkeoluRoBsQ4ug0uNZgsuMhrWRM4ag7Mo2QFO5+FvHkT/6JV5rD7kfW" +
            "aLa3ZofC/pCjW15gKP0E7+qII3Ps9gui9jfkzaobYInWwLVhqOUg55beJ98=");
    var dhGenerator = base64.parse("AAU=");
    var invalidPubKey = new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    //Random pub key
    var randPubkey = new Uint8Array([157,193,10,17,136,207,227,77,9,53,388,96,213,9,65,218]); 
    var genPubkey = undefined,
        genPrivkey = undefined;
   
	var listofOperations = [                    
	    {
			name: "DeriveDHKey",
			algo: { name: "DH", params: { public: randPubkey } },
			derivedKeyAlgo: "AES-CBC",
			extractable: true,
			usages: ["encrypt", "decrypt"],
			result: "pass"
		},	
		
		{
			//Derive passes but export of private key will not
			name: "DeriveNonExtractableDHKey",
			algo: { name: "DH", params: { public: randPubkey } },
			derivedKeyAlgo: "AES-CBC",
			extractable: false,
			usages: ["encrypt", "decrypt"],
			result: "pass"
		},	
		
		{   //Derived key uses SHA-384, derive passes but export will fail since its SHA-384
			name: "DeriveDiffKeyAlgo",
			algo: { name: "DH", params: { public: randPubkey } },
			derivedKeyAlgo: "SHA-384",
			extractable: true,
			usages: ["encrypt", "decrypt"],
			result: "pass"
		},	
		
		{
			name: "DeriveDHKeyDiffUsage",
			algo: { name: "DH", params: { public: randPubkey } },
			derivedKeyAlgo: "AES-CBC",
			extractable: true,
			usages: ["derive"],
			result: "pass"
		},	
		
		{
			name: "DeriveDHKeyInvalidAlgoName",
			algo: { name: "HMAC", params: { public: randPubkey } },
			derivedKeyAlgo: "AES-CBC",
			extractable: true,
			usages: ["encrypt", "decrypt"],
			deriveKey: false
		},	
		
		{   //Fails since derive algo DH does not match generate algo RSASSA-PKCS1-v1_5
			name: "DeriveAlgoMismatchGenerate",
			algo: { name: "DH", params: { public: randPubkey } },
			derivedKeyAlgo: "AES-CBC",
			extractable: true,
			usages: ["encrypt", "decrypt"],
			deriveKey: false
		},	
		
		{   //Using a pubkey of all zeros
			name: "DeriveDHKeyInvalidPublicKey",
			algo: { name: "DH", params: { public: invalidPubKey } },
			derivedKeyAlgo: "AES-CBC",
			extractable: true,
			usages: ["encrypt", "decrypt"],
			deriveKey: false
		},	
		
		{   //Make the prime of the baseKey some rand chars
			//Test passes since keyHandle is being used and not invalid base key does
			//not affect key object
			name: "DeriveDHKeyInvalidBaseKey",
			algo: { name: "DH", params: { public: randPubkey } },
			derivedKeyAlgo: "AES-CBC",
			extractable: true,
			usages: ["encrypt", "decrypt"],
			result: "pass"
		},
		
		{  //Generated key has derive in the usage hence this passes
		   //The derived key usage is based on the usage specified as input to derive	
			name: "GeneratedKeyUsageMismatch",
			algo: { name: "DH", params: { public: randPubkey } },
			derivedKeyAlgo: "AES-CBC",
			extractable: true,
			usages: ["encrypt"],
			result: "pass"
		},	
		
		{  
			name: "GeneratedKeyUsageNotDerive",
			algo: { name: "DH", params: { public: randPubkey } },
			derivedKeyAlgo: "AES-CBC",
			extractable: true,
			usages: ["derive"],
			deriveKey: false
		},	
		
		
		

	];
	var opIndex = 0;
	var indexValue = 0;
	function wrapperForTest(opIndex) {	
		it(listofOperations[opIndex].name, function () {
	      
			indexValue = listofOperations[opIndex];
			var error = undefined;
			var privkeyData = undefined, 
			    pubkeyData = undefined;
			var sharedKey = undefined;
			    
			//Generate key pair first then derive
			//This is because the generate creates a "secret" in crypto context which is required for derive key 
            runs(function () {
            	try {
            		error = undefined;
            		genPubkey = undefined;
            		genPrivkey = undefined;
            		var op = undefined;
            		if (indexValue.name == "DeriveAlgoMismatchGenerate") {
            			var fermatF4 = new Uint8Array([0x01, 0x00, 0x01]);
            			op = nfCrypto.generateKey({
							name: "RSASSA-PKCS1-v1_5",
							params: {
								modulusLength: 512,
								publicExponent: fermatF4,
							},
						});
            		} else if (indexValue.name == "GeneratedKeyUsageNotDerive") {  
            			op = nfCrypto.generateKey( {name: "DH", params: { prime: dhPrime, generator: dhGenerator } }, true, ["encrypt"] );
         	           
            		} else {
    	                op = nfCrypto.generateKey( {name: "DH", params: { prime: dhPrime, generator: dhGenerator } }, true, ["derive", "decrypt"] );
    	            }
            		op.onerror = function (e) {
	                    error = "ERROR";
	                };
	                op.oncomplete = function (e) {
	                	genPubkey  = e.target.result.publicKey;
	                	genPrivkey = e.target.result.privateKey;
	                };
				} catch(e) {
					error = "ERROR";
				}
            });
            waitsFor(function () {
                return genPubkey || genPrivkey || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(genPubkey).toBeDefined();
                expect(genPrivkey).toBeDefined();
            });
            //Derive key from generate key
			runs(function () {
				try {
					error = undefined;
					sharedKey = undefined;
					//invalidating the basekey
					if(indexValue.name == "DeriveDHKeyInvalidBaseKey") {
						//rand characters
						genPubkey.algorithm.params.prime = "bkeoluRoBsQ4ug0uNZgsuMhrWRM4ag7"; 
						indexValue.baseKey = genPubkey ;
					} else {
						indexValue.baseKey = genPubkey;
					}
					var op = nfCrypto.deriveKey( indexValue.algo, indexValue.baseKey, indexValue.derivedKeyAlgo, indexValue.extractable, indexValue.usages);
					op.onerror = function (e) {
						error = "ERROR";
					};
					op.oncomplete = function (e) {
						sharedKey  = e.target.result;
					};
				} catch(e) {
					error = "ERROR";
				}
			});

			waitsFor(function () {
				 return sharedKey || error;
			});

			runs(function () {
				if(indexValue.deriveKey == false) {
					expect(error).toBeDefined();
					expect(sharedKey).toBeUndefined();	
				} else {
					//shared key checks
					expect(error).toBeUndefined();
					expect(algorithmName(sharedKey.algorithm)).toEqual(indexValue.derivedKeyAlgo);
					expect(sharedKey.extractable).toEqual(indexValue.extractable);
					expect(sharedKey.keyUsage.length).toEqual(indexValue.usages.length);
					if(indexValue.usages.length > 1) {
						expect(sharedKey.keyUsage[0]).toEqual(indexValue.usages[0]);
						expect(sharedKey.keyUsage[1]).toEqual(indexValue.usages[1]);
					} else {
						expect(sharedKey.keyUsage[0]).toEqual(indexValue.usages[0]);
					}
					expect(sharedKey.handle).not.toEqual(0);
					expect(sharedKey.type).toEqual("secret");
				}
			});
			
			if(indexValue.deriveKey != false) {
				//Export shared key
				runs(function () {
					try {
						error = undefined;
						var op = nfCrypto.exportKey("raw", sharedKey);
						op.onerror = function (e) {
							error = "ERROR";
						};
						op.oncomplete = function (e) {
							pubkeyData = e.target.result;
						};
					} catch(e) {
						error = "ERROR";
					}
				});

				waitsFor(function () {
					return pubkeyData || error;
				});

				runs(function () {
					if(indexValue.result == "fail" || indexValue.deriveKey == false || indexValue. name == "DeriveNonExtractableDHKey" || indexValue. name == "DeriveDiffKeyAlgo") {
						expect(error).toBeDefined();
						expect(pubkeyData).toBeUndefined();
					} else {
						expect(error).toBeUndefined();
						expect(pubkeyData).toBeDefined();
						//Check that keyData is not a bunch of zeros
						expect(base16.stringify(pubkeyData)).not.toEqual(base16.stringify([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
					}
				});
			}//if(indexValue.deriveKey != false) 
		});//it
	}//function wrapperForTest
	for(opIndex = 0; opIndex < listofOperations.length; opIndex++) {	
		wrapperForTest(opIndex);
	}
});//describe
