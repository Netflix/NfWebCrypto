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

describe("generate", function () {

	var listofOperations = [
	    {
			name: "GenerateExtractable",
			algo: { name: "AES-CBC", params: { length: 128 } },
			extractable: true,
			//since its AES
			type: "secret",
			usages: [],
			result: "pass"
		},  
		{
			name: "GenerateNonExtractable",
			algo: { name: "AES-CBC", params: { length: 128 } },
			extractable: false,
			type: "secret",
			usages: [],
			result: "fail"
		},   
		{
			name: "GenerateKeyInvalidUsage",
			algo: { name: "AES-CBC", params: { length: 128 } },
			extractable: true,
			type: "secret",
			//Since AES key is not used for sign/verify
			usages: ["sign", "verify"],
			//Flag that indicates genKey will fail
			genKey: false
		},  
		{
		    //There are no checks on short keys
			name: "GenerateAESShortKey",
			algo: { name: "AES-CBC", params: { length: 8 } },
			extractable: true,
			//since its AES
			type: "secret",
			usages: [],
			result: "pass"
		},  
		{
			//Generate/export pass but keyType check is different
			name: "GenerateWrongSymmetricKeyType",
			algo: { name: "AES-CBC", params: { length: 128 } },
			extractable: true,
			//Since all symmetric keys are secret
			type: "public",
			usages: [],
			result: "pass"
		}, 
		{
			name: "GenerateWrongAlgo",
			algo: { name: "foo", params: { length: 128 } },
			extractable: true,
			type: "secret",
			usages: [],
			//Flag that indicates genKey will fail
			genKey: false
		},  
		{
			name: "GenerateHMACKey",
			//Length of key is 256
			algo: { name: "HMAC", params: { hash: {name: "SHA-256"} } },
			extractable: true,
			type: "secret",
			usages: [],
			keyLength: "256",
			result: "pass"
		},  
		{
			name: "GenerateHMACNonExtractableKey",
			algo: { name: "HMAC", params: { hash: {name: "SHA-256"} } },
			extractable: false,
			type: "secret",
			usages: [],
			keyLength: "256",
			result: "fail"
		},  
		{
			name: "GenerateHMACInvalidKeyLength",
			//Since the number after SHA is used as key length
			algo: { name: "HMAC", params: { hash: {name: "SHA"} } },
			extractable: true,
			type: "secret",
			usages: [],
			//Flag that indicates genKey will fail
			genKey: false
		},  
		{
			name: "GenerateHMACKeyInvalidUsage",
			//Will fail since HMAC is not used for encrypt decrypt
			algo: { name: "HMAC", params: { hash: {name: "SHA-256"} } },
			extractable: true,
			type: "secret",
			usages: ["encrypt", "decrypt"],
			//Flag that indicates genKey will fail
			genKey: false
		},
		{
			//Generate/export pass but keyType check is different
			name: "GenerateHMACKeyInvalidType",
			//Since the number after SHA is used as key length
			algo: { name: "HMAC", params: { hash: {name: "SHA-256"} } },
			extractable: true,
			type: "public",
			usages: [],
			keyLength: "256",
			result: "pass"
		},  
		{
			name: "GenerateWrongAsymmetricKeyUsage",
			algo: { name: "RSAES-PKCS1-v1_5", params: { modulusLength: 512, publicExponent: new Uint8Array([0x01, 0x00, 0x01]) } },
			extractable: true,
			usages: ["sign", "verify"],
			//Flag that indicates genKey will fail
			genKey: false
			
		}, 
		{
			name: "GenerateMissingRsaKeyParams",
			algo: { name: "RSAES-PKCS1-v1_5", params: {} },
			extractable: true,
			type: "public",
			usages: [],
			//Flag that indicates genKey will fail
			genKey: false
		},
		{
			//All zeros exponent
			name: "GenerateEmptyRsaKeyExponent",
			algo: { name: "RSAES-PKCS1-v1_5", params: { modulusLength: 512, publicExponent: new Uint8Array([]) } },
			extractable: true,
			type: "public",
			//Flag that indicates genKey will fail
			genKey: false
		},
		{
			name: "GenerateWrongRsaKeyLength",
			algo: { name: "RSAES-PKCS1-v1_5", params: { modulusLength: 16, publicExponent: new Uint8Array([0x01, 0x00, 0x01]) } },
			extractable: true,
			type: "public",
			//Flag that indicates genKey will fail
			genKey: false
		} 
		
	];
	var opIndex = 0;
	var indexValue = 0;
	function wrapperForTest(opIndex) {	
		it(listofOperations[opIndex].name, function () {
			indexValue = listofOperations[opIndex];
			var error = undefined;
			var key = undefined;
			var keyData = undefined;

			runs(function () {
				try {
					var op = nfCrypto.generateKey(indexValue.algo, indexValue.extractable, indexValue.usages);
					op.onerror = function (e) {
						error = "ERROR";
					};
					op.oncomplete = function (e) {
						key = e.target.result;
					};
				} catch(e) {
					error = "ERROR";
				}
			});

			waitsFor(function () {
				return key || error;
			});

			runs(function () {
				if(indexValue.genKey == false) {
					expect(error).toBeDefined();
					expect(key).toBeUndefined();	
				} else {
					expect(error).toBeUndefined();
					expect(key.algorithm.name).toEqual(indexValue.algo.name);
					expect(key.extractable).toEqual(indexValue.extractable);
					expect(key.keyUsage.length).toEqual(indexValue.usages.length);
					//TODO
					//expect(key.keyUsage[0]).toEqual(indexValue.usages[0]);
					expect(key.handle).not.toEqual(0);
					if (indexValue.name == "GenerateWrongSymmetricKeyType" || indexValue.name == "GenerateWrongAsymmetricKeyType"
						|| indexValue.name == "GenerateHMACKeyInvalidType") {
						expect(key.type).toNotEqual(indexValue.type);
					} else {
						expect(key.type).toBe(indexValue.type);
					}
				}
			});
			
			runs(function () {
				try {
					var op = nfCrypto.exportKey("raw", key);
					op.onerror = function (e) {
						error = "ERROR";
					};
					op.oncomplete = function (e) {
						keyData = e.target.result;
					};
				} catch(e) {
					error = "ERROR";
				}
			});

			waitsFor(function () {
				return keyData || error;
			});

			runs(function () {
				if(indexValue.result == "fail" || indexValue.genKey == false) {
					expect(error).toBeDefined();
					expect(keyData).toBeUndefined();
				}
				else {
					expect(error).toBeUndefined();
					expect(keyData).toBeDefined();
					if (indexValue.name == "GenerateHMACKey" || indexValue.name == "GenerateHMACKeyInvalidType") {
						expect(keyData.length).toEqual(indexValue.keyLength/8);
					} else {
						expect(keyData.length).toEqual(indexValue.algo.params.length/8);
					}
					expect(base16.stringify(keyData)).not.toEqual(base16.stringify([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
				}
			});
		});//it
	}//function wrapperForTest
	for(opIndex = 0; opIndex < listofOperations.length; opIndex++) {	
		wrapperForTest(opIndex);
	}
});//describe

describe("generateRSAES", function () {

	var listofOperations = [
	   
		{
			name: "GenerateNonExtractableAsymmetricKey",
			algo: { name: "RSAES-PKCS1-v1_5", params: { modulusLength: 512, publicExponent: new Uint8Array([0x01, 0x00, 0x01]) } },
			extractable: false,
			usages: ["encrypt", "decrypt"],
			type: ["public", "private"],
			result: "pass"
		}, 
		{
			name: "GenerateRsaKey",
			algo: { name: "RSAES-PKCS1-v1_5", params: { modulusLength: 512, publicExponent: new Uint8Array([0x01, 0x00, 0x01]) } },
			extractable: true,
			usages: ["encrypt", "decrypt"],
			type: ["public", "private"],
			result: "pass"
		} 
		
	];
	var opIndex = 0;
	var indexValue = 0;
	function wrapperForTest(opIndex) {	
		it(listofOperations[opIndex].name, function () {
			indexValue = listofOperations[opIndex];
			var error = undefined;
			var privKey = undefined, 
			    pubKey = undefined;
			var privkeyData = undefined, 
			    pubkeyData = undefined;

			runs(function () {
				try {
					var op = nfCrypto.generateKey(indexValue.algo, indexValue.extractable, indexValue.usages);
					op.onerror = function (e) {
						error = "ERROR";
					};
					op.oncomplete = function (e) {
						pubKey  = e.target.result.publicKey;
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
				if(indexValue.genKey == false) {
					expect(error).toBeDefined();
					expect(pubKey).toBeUndefined();	
					expect(privKey).toBeUndefined();	
				} else {
					//Public key checks
					expect(error).toBeUndefined();
					expect(pubKey.algorithm.name).toEqual(indexValue.algo.name);
					if (indexValue.name == "GenerateNonExtractableAsymmetricKey") {
						//public keys are always extractable and override api params
						expect(pubKey.extractable).toBeTruthy();
					} else {
						expect(pubKey.extractable).toEqual(indexValue.extractable);
					}
					expect(pubKey.keyUsage.length).toEqual(indexValue.usages.length);
					if(indexValue.usages.length > 1) {
						expect(pubKey.keyUsage[0]).toEqual(indexValue.usages[0]);
						expect(pubKey.keyUsage[1]).toEqual(indexValue.usages[1]);
					} else {
						expect(pubKey.keyUsage[0]).toEqual(indexValue.usages[0]);
					}
					expect(pubKey.handle).not.toEqual(0);
					expect(pubKey.type).toBe(indexValue.type[0]);
					//Priv key checks
					expect(privKey.algorithm.name).toEqual(indexValue.algo.name);
					expect(privKey.extractable).toEqual(indexValue.extractable);
					expect(privKey.keyUsage.length).toEqual(indexValue.usages.length);
					if(indexValue.usages.length > 1) {
						expect(privKey.keyUsage[0]).toEqual(indexValue.usages[0]);
						expect(privKey.keyUsage[1]).toEqual(indexValue.usages[1]);	
					} else {
						expect(privKey.keyUsage[0]).toEqual(indexValue.usages[0]);
					}
					expect(privKey.handle).not.toEqual(0);
					expect(privKey.type).toBe(indexValue.type[1]);	
				}
			});
		});//it
	}//function wrapperForTest
	for(opIndex = 0; opIndex < listofOperations.length; opIndex++) {	
		wrapperForTest(opIndex);
	}
});//describe