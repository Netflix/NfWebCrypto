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
    
	it("DigestSHA384", function () {
		// convenient calculator here: http://www.fileformat.info/tool/hash.htm
		var data = hex2abv("6162636462636465636465666465666765666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f7071");
		var result_sha384_hex = "3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b";
		var op,
		result,
		error,
		complete;

		runs(function () {
			op = nfCrypto.digest("SHA-384", data)
			op.onerror = function (e) {
				error = "ERROR :: " + e.target.result;
			};
			op.oncomplete = function (e) {
				complete = true;
				result = e.target.result;
			};
		});

		waitsFor(function () {
			return error || complete;
		});

		runs(function () {
			expect(error).toBeUndefined();
			expect(complete).toBeTruthy();
			expect(abv2hex(result)).toBe(result_sha384_hex);
		});
	});//end of it("DigestSHA384")

	//Compare golden data against webcrypto "digest" method using SHA1 
	it("DigestSHA1", function () {
		// GoldenData form http://www.fileformat.info/tool/hash.htm
		var data = hex2abv("6162636462636465636465666465666765666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f7071");
		var result_sha1_hex = "84983e441c3bd26ebaae4aa1f95129e5e54670f1";

		var op,
		result,
		error,
		complete;

		runs(function () {
			op = nfCrypto.digest("SHA-1", data)
			op.onerror = function (e) {
				error = "ERROR :: " + e.target.result;
			};
			op.oncomplete = function (e) {
				complete = true;
				result = e.target.result;
			};
		});

		waitsFor(function () {
			return error || complete;
		});

		runs(function () {
			expect(error).toBeUndefined();
			expect(complete).toBeTruthy();
			expect(abv2hex(result)).toBe(result_sha1_hex);
		});
	});

	//Compare golden data against webcrypto "digest" method using SHA256 
	it("DigestSHA256", function () {
		//GoldenData form http://www.fileformat.info/tool/hash.htm
		var data = hex2abv("6162636462636465636465666465666765666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f7071");
		var result_sha256_hex = "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1";

		var op,
		result,
		error,
		complete;

		runs(function () {
			op = nfCrypto.digest("SHA-256", data)
			op.onerror = function (e) {
				error = "ERROR :: " + e.target.result;
			};
			op.oncomplete = function (e) {
				complete = true;
				result = e.target.result;
			};
		});

		waitsFor(function () {
			return error || complete;
		});

		runs(function () {
			expect(error).toBeUndefined();
			expect(complete).toBeTruthy();
			expect(abv2hex(result)).toBe(result_sha256_hex);
		});
	});

	//Compare golden data against webcrypto "digest" method using SHA512
	it("DigestSHA512", function () {
		// GoldenData form http://www.fileformat.info/tool/hash.htm
		var data = hex2abv("6162636462636465636465666465666765666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f7071");
		var result_sha512_hex = "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445";

		var op,
		result,
		error,
		complete;

		runs(function () {
			op = nfCrypto.digest("SHA-512", data)
			op.onerror = function (e) {
				error = "ERROR :: " + e.target.result;
			};
			op.oncomplete = function (e) {
				complete = true;
				result = e.target.result;
			};
		});

		waitsFor(function () {
			return error || complete;
		});

		runs(function () {
			expect(error).toBeUndefined();
			expect(complete).toBeTruthy();
			expect(abv2hex(result)).toBe(result_sha512_hex);
		});
	});

	//Error digest tests

	//Trying to digest empty data
	it("DigestSHA384EmptyData", function () {
		var data = hex2abv("");

		var op,
		result,
		error,
		complete;

		runs(function () {
			op = nfCrypto.digest("SHA-384", data)
			op.onerror = function (e) {
				error = "ERROR";
			};
			op.oncomplete = function (e) {
				complete = e.target.result;
			};
		});

		waitsFor(function () {
			return error || complete;
		});

		runs(function () {
			expect(error).toBe("ERROR");
			expect(complete).toBeUndefined;
			//expect(abv2hex(result)).toBe(result_sha384_hex);
		});
	});

	//Trying to digest null data
	it("DigestSHA384NullData", function () {
		var data = null;

		var op,
		result,
		error,
		complete;

		runs(function () {
			op = nfCrypto.digest("SHA-384", data)
			op.onerror = function (e) {
				error = "ERROR";
			};
			op.oncomplete = function (e) {
				complete = e.target.result;
			};
		});

		waitsFor(function () {
			return error || complete;
		});

		runs(function () {
			expect(error).toBe("ERROR");
			expect(complete).toBeUndefined;
		});
	});
	
	//Sending invalid digest algorithm
	it("DigestInvalidAlgo", function () {
		
		var data = hex2abv("6162636462636465636465666465666765666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f7071");
		
		var op,
		result,
		error,
		complete;

		runs(function () {
			op = nfCrypto.digest("sha", data)
			op.onerror = function (e) {
				error = "ERROR";
			};
			op.oncomplete = function (e) {
				complete = e.target.result;
			};
		});

		waitsFor(function () {
			return error || complete;
		});

		runs(function () {
			expect(error).toBe("ERROR");
			expect(complete).toBeUndefined;
		});
	});
	
	//Setting invalid digest algorithm to sign/verify algo
	it("DigestInvalidAlgoType", function () {
		
		var data = hex2abv("6162636462636465636465666465666765666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f7071");
		
		var op,
		result,
		error,
		complete;

		runs(function () {
			op = nfCrypto.digest("HMAC", data)
			op.onerror = function (e) {
				error = "ERROR";
			};
			op.oncomplete = function (e) {
				complete = e.target.result;
			};
		});

		waitsFor(function () {
			return error || complete;
		});

		runs(function () {
			expect(error).toBe("ERROR");
			expect(complete).toBeUndefined;
		});
	});

});//end of describe("Digest")