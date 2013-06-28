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

describe("generatexportdhkey", function () {

	var dhPrime = base64.parse(
             "lpTp2Nk6WsdMUJtLvOhekhMs0ZzOR30afkfVJ9nsKRUV8Liz4ertUAbh" +
             "sbkeoluRoBsQ4ug0uNZgsuMhrWRM4ag7Mo2QFO5+FvHkT/6JV5rD7kfW" +
             "aLa3ZofC/pCjW15gKP0E7+qII3Ps9gui9jfkzaobYInWwLVhqOUg55beJ98=");
    var dhGenerator = base64.parse("AAU=");
    var invalidPrime = new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    var invalidGenerator = new Uint8Array([]);
    
	var listofOperations = [
	    {
			name: "GenerateDHKey",
			algo: { name: "DH", params: { prime: dhPrime, generator: dhGenerator } },
			extractable: true,
			type: ["public", "private"],
			usages: ["encrypt", "decrypt"],
			result: "pass"
		},
		
		{
			//Only public key can be exported since public keys are always extractable
			//Private key will not be exported
			name: "GenerateNonExtractableDHKey",
			algo: { name: "DH", params: { prime: dhPrime, generator: dhGenerator } },
			extractable: false,
			type: ["public", "private"],
			usages: ["encrypt", "decrypt"],
			result: "pass"
		},
		
		{
			//No negative usage case since DH supports all usages
			name: "GenerateDHKeyDiffUsage",
			algo: { name: "DH", params: { prime: dhPrime, generator: dhGenerator } },
			extractable: true,
			type: ["public", "private"],
			usages: ["derive"],
			result: "pass"
		},
		
		{
			name: "GenerateDHKeyWithInvalidAlgo",
			algo: { name: "foo", params: { prime: dhPrime, generator: dhGenerator } },
			extractable: true,
			type: ["public", "private"],
			usages: ["encrypt", "decrypt"],
			genKey: false
		},
		
		{
			name: "GenerateDHKeyInvalidPrime",
			algo: { name: "DH", params: { prime: invalidPrime, generator: dhGenerator } },
			extractable: true,
			type: ["public", "private"],
			usages: ["encrypt", "decrypt"],
			genKey: false
		},
		
		{
			name: "GenerateDHKeyEmptyGenerator",
			algo: { name: "DH", params: { prime: dhPrime, generator: invalidGenerator } },
			extractable: true,
			type: ["public", "private"],
			usages: ["encrypt", "decrypt"],
			genKey: false
		},
		
		  
	];
	var opIndex = 0;
	var indexValue = 0;
	function wrapperForTest(opIndex) {	
		it(listofOperations[opIndex].name, function () {
			indexValue = listofOperations[opIndex];
			var error = undefined;
			var pubKey = undefined, 
			    privKey = undefined;
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
					if (indexValue.name == "GenerateNonExtractableDHKey") {
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
			//Export public key
			runs(function () {
				try {
					var op = nfCrypto.exportKey("raw", pubKey);
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
				if(indexValue.result == "fail" || indexValue.genKey == false) {
					expect(error).toBeDefined();
					expect(pubkeyData).toBeUndefined();
				}
				else {
					expect(error).toBeUndefined();
					expect(pubkeyData).toBeDefined();
				    //Check that keyData is not a bunch of zeros
					expect(base16.stringify(pubkeyData)).not.toEqual(base16.stringify([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
				}
			});
			
			//Export private key
			runs(function () {
				try {
					var op = nfCrypto.exportKey("raw", privKey);
					op.onerror = function (e) {
						error = "ERROR";
					};
					op.oncomplete = function (e) {
						privkeyData = e.target.result;
					};
				} catch(e) {
					error = "ERROR";
				}
			});

			waitsFor(function () {
				return privkeyData || error;
			});

			runs(function () {
				if(indexValue.result == "fail" || indexValue.name == "GenerateNonExtractableDHKey" || indexValue.genKey == false) {
					expect(error).toBeDefined();
					expect(privkeyData).toBeUndefined();
				}
				else {
					expect(error).toBeUndefined();
					expect(privkeyData).toBeDefined();
				    //Check that keyData is not a bunch of zeros
					expect(base16.stringify(privkeyData)).not.toEqual(base16.stringify([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
				}
			});
		});//it
	}//function wrapperForTest
	for(opIndex = 0; opIndex < listofOperations.length; opIndex++) {	
		wrapperForTest(opIndex);
	}
});//describe