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

describe("getkey", function () {

	var listofOperations = [
	    {
			name: "GetKeyKde",
			keyName: "Kde",
			getKey: true,
			result: "pass"
		},  
		{
			name: "GetKeyKdh",
			keyName: "Kdh",
			getKey: true,
			result: "pass"
		},
        {
            name: "GetKeyKdw",
            keyName: "Kdw",
            getKey: true,
            result: "pass"
        },
        {
            name: "GetKeyKds",
            keyName: "Kdw",
            getKey: true,
            result: "pass"
        },
		{
			name: "GetEmptyKey",
			keyName: "",
		    getKey: false,
			result: "pass"
		},
		{
			name: "GetInvalidKey",
			keyName: "foo",
		    getKey: false,
			result: "pass"
		},
		{
			name: "GetNullKey",
			keyName: null,
		    getKey: false,
			result: "pass"
		}
		
	];
	var opIndex = 0;
	var indexValue = 0;
	function wrapperForTest(opIndex) {	
		it(listofOperations[opIndex].name, function () {
			indexValue = listofOperations[opIndex];
			var error = undefined;
			var keyName = undefined;
			var key = undefined;

			runs(function () {
				try {
					var op = nfCryptoKeys.getKeyByName(indexValue.keyName);
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
				if(indexValue.getKey == false) {
					expect(error).toBeDefined();
					expect(key).toBeUndefined();	
				} else {
					expect(error).toBeUndefined();
					expect(key.type).toBe("secret");
                    expect(key.extractable).toBe(false);
                    expect(key.name).toBe(indexValue.keyName);
                    expect(key.id).toBeDefined();
                    if (indexValue.name == "GetKeyKde") {
                        expect(key.algorithm.name).toBe("AES-CBC");
                        expect(JSON.stringify(key.keyUsage)).toBe(JSON.stringify(['encrypt', 'decrypt']));
                    } else if (indexValue.name == "GetKeyKdh") {
                        expect(key.algorithm.name).toBe("HMAC");
                        expect(JSON.stringify(key.keyUsage)).toBe(JSON.stringify(['sign', 'verify']));
                    } else {
                        expect(key.algorithm.name).toBe("AES-KW");
                        expect(JSON.stringify(key.keyUsage)).toBe(JSON.stringify(['wrap', 'unwrap']));
                    }
				}
			});
			
		});//it
	}//function wrapperForTest
	for(opIndex = 0; opIndex < listofOperations.length; opIndex++) {	
		wrapperForTest(opIndex);
	}
});//describe