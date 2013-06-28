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

describe("digest", function () {

	//Global
	// convenient calculator here: http://www.fileformat.info/tool/hash.htm
	var listofOperations = [
	                        {
	                        	name: "DigestSHA384",
	                        	algo: "SHA-384",
	                        	data: base16.parse("6162636462636465636465666465666765666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f7071"),
	                        	result: "3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b"
	                        },

	                        {
	                        	name: "DigestSHA1",
	                        	algo: "SHA-1",
	                        	data: base16.parse("6162636462636465636465666465666765666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f7071"),
	                        	result: "84983e441c3bd26ebaae4aa1f95129e5e54670f1"	
	                        },
	                        
	                        {
	                        	name: "DigestSHA256",
	                        	algo: "SHA-256",
	                        	data: base16.parse("6162636462636465636465666465666765666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f7071"),
	                        	result: "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
	                        },
	                        
	                        {
	                        	name: "DigestSHA512",
	                        	algo: "SHA-512",
	                        	data: base16.parse("6162636462636465636465666465666765666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f7071"),
	                			result: "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445"    	
	                        },
	                        
	                        {
	                        	name: "DigestSHA384EmptyData",
	                        	algo: "SHA-384",
	                        	data: new Uint8Array([]),
	                        	result: "fail",
	                        },
	                        
	                        {
	                        	name: "DigestSHA384NullData",
	                        	algo: "SHA-384",
	                        	data: null,
	                        	result: "fail"
	                        },
	                        
	                        {
	                        	name: "DigestInvalidAlgo",
	                        	algo: "sha",
	                        	data: base16.parse("6162636462636465636465666465666765666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f7071"),
	                        	result: "fail"
	                        },
	                        
	                        {
	                        	name: "DigestInvalidAlgoType",
	                        	algo: "HMAC",
	                        	data: base16.parse("6162636462636465636465666465666765666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f7071"),
	                        	result: "fail"
	                        }
	                        ];
	var opIndex = 0;
	var indexValue = 0;
	function wrapperForTest(opIndex) {
		it(listofOperations[opIndex].name, function () {
			indexValue = listofOperations[opIndex];
			var op = undefined;
			var localResult = undefined,
			error = undefined,
			complete = undefined;

			runs(function () {
				try {
					console.log("Test being run is " + JSON.stringify(indexValue.algo));
					op = nfCrypto.digest(indexValue.algo, indexValue.data)
					op.onerror = function (e) {
						error = "ERROR";
					};
					op.oncomplete = function (e) {
						complete = true;
						localResult = e.target.result;
					};
				} catch(e) {
					error = "ERROR";
				}
			});

			waitsFor(function () {
				return error || complete;
			});

			runs(function () {
				//When expecting errors
				if(indexValue.result == "fail") {
					expect(error).toBe("ERROR");
					expect(complete).toBeUndefined;
				} else {
					expect(error).toBeUndefined();
					expect(complete).toBeTruthy();
					expect(base16.stringify(localResult)).toBe(indexValue.result);
				}	
			});
		});//it	
	}//wrapperForTests
	for(opIndex = 0; opIndex < listofOperations.length; opIndex++) {	
		wrapperForTest(opIndex);
	}
});//describe