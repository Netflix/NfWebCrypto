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

describe("SignVerifyHMAC", function () {


	//Global
	var DATA = hex2abv("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
	var KEY = undefined;

	beforeEach(function () {
		var error = undefined;

		keyData = new Uint8Array([
		                          0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
		                          0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
		                          ]);

		runs(function () {
			var op = nfCrypto.importKey("raw", keyData, { name: "HMAC", params: { hash: "SHA-256" } }, true, ["sign", "verify"]);
			op.onerror = function (e) {
				error = "ERROR";
			};
			op.oncomplete = function (e) {
				KEY = e.target.result;
			};
		});

		waitsFor(function () {
			return KEY || error;
		});

		runs(function () {
			expect(error).toBeUndefined();
			expect(KEY).toBeDefined();
		});
	});//beforeEach	
	
	afterEach(function () {
		KEY = undefined;
	});

	//Checks that sign/verify happy path works
	//Additionally checks that invalid signature is not verified
	it("SignVerifyHappyPath", function () {
		var error = undefined;
		var signature = undefined;
		var verified = undefined;

		runs(function () {
			error = undefined;
			var signOp = nfCrypto.sign({
				name: "HMAC",
				params: { hash: "SHA-256" }
			}, KEY, DATA);
			signOp.onerror = function (e) {
				error = "ERROR";
			};
			signOp.oncomplete = function (e) {
				signature = e.target.result;
			};
		});

		waitsFor(function () {
			return signature || error;
		});

		runs(function () {
			expect(error).toBeUndefined();
			expect(signature).toBeDefined();
		});

		runs(function () {
			error = undefined;
			var signOp = nfCrypto.verify({
				name: "HMAC",
				params: { hash: "SHA-256" }
			}, KEY, signature, DATA);
			signOp.onerror = function (e) {
				error = "ERROR";
			};
			signOp.oncomplete = function (e) {
				verified = e.target.result;
			};
		});

		waitsFor(function () {
			return verified !== undefined || error;
		});

		runs(function () {
			expect(error).toBeUndefined();
			expect(verified).toBe(true);
		});
	});//it("SignVerify")

	//Test for verify with empty data
	it("VerifyEmptyData", function () {
		var error = undefined;
		var verified = undefined;
		var data = hex2abv("");
		var signature = undefined;

		runs(function () {
			error = undefined;
			var signOp = nfCrypto.sign({
				name: "HMAC",
				params: { hash: "SHA-256" }
			}, KEY, DATA);
			signOp.onerror = function (e) {
				error = "ERROR";
			};
			signOp.oncomplete = function (e) {
				signature = e.target.result;
			};
		});

		waitsFor(function () {
			return signature || error;
		});

		runs(function () {
			expect(error).toBeUndefined();
			expect(signature).toBeDefined();
		});
		runs(function () {
			error = undefined;
			var signOp = nfCrypto.verify({
				name: "HMAC",
				params: { hash: "SHA-256" }
			}, KEY, signature, data);
			signOp.onerror = function (e) {
				error = "ERROR";
			};
			signOp.oncomplete = function (e) {
				verified = e.target.result;
			};
		});
		waitsFor(function () {
			return verified || error;
		});

		runs(function () {
			expect(error).toBe("ERROR");
			expect(verified).toBeUndefined();
		});
	});//it("VerifyEmptyData")

	//Test for verify with null data
	it("VerifyNullData", function () {
		var error = undefined;
		var verified = undefined;
		var data = null;
		var signature = undefined;

		runs(function () {
			error = undefined;
			var signOp = nfCrypto.sign({
				name: "HMAC",
				params: { hash: "SHA-256" }
			}, KEY, DATA);
			signOp.onerror = function (e) {
				error = "ERROR";
			};
			signOp.oncomplete = function (e) {
				signature = e.target.result;
			};
		});

		waitsFor(function () {
			return signature || error;
		});

		runs(function () {
			expect(error).toBeUndefined();
			expect(signature).toBeDefined();
		});
		runs(function () {
			var signOp = nfCrypto.verify({
				name: "HMAC",
				params: { hash: "SHA-256" }
			}, KEY, signature, data);
			signOp.onerror = function (e) {
				error = "ERROR";
			};
			signOp.oncomplete = function (e) {
				verified = e.target.result;
			};
		});
		waitsFor(function () {
			return verified || error;
		});

		runs(function () {
			expect(error).toBe("ERROR");
			expect(verified).toBeUndefined();
		});
	});//it("VerifyNullData")

	//Test for verify with invalid algo
	it("VerifyInvalidAlgo", function () {
		var error = undefined;
		var verified = undefined;
		var data = null;
		var signature = undefined;

		runs(function () {
			var signOp = nfCrypto.sign({
				name: "HMAC",
				params: { hash: "SHA-256" }
			}, KEY, DATA);
			signOp.onerror = function (e) {
				error = "ERROR";
			};
			signOp.oncomplete = function (e) {
				signature = e.target.result;
			};
		});
		waitsFor(function () {
			return signature || error;
		});
		runs(function () {
			expect(error).toBeUndefined();
			expect(signature).toBeDefined();
		});
		runs(function () {
			var signOp = nfCrypto.verify({
				name: "hmac",
				params: { hash: "SHA-256" }
			}, KEY, signature, data);
			signOp.onerror = function (e) {
				error = "ERROR";
			};
			signOp.oncomplete = function (e) {
				verified = e.target.result;
			};
		});
		waitsFor(function () {
			return verified || error;
		});

		runs(function () {
			expect(error).toBe("ERROR");
			expect(verified).toBeUndefined();
		});
	});//it("VerifyInvalidAlgo")

	//Test for verify with invalid algo type since SHA1 is a digest algo
	it("VerifyInvalidAlgoType", function () {
		var error = undefined;
		var verified = undefined;
		var data = null;
		var signature = undefined;

		runs(function () {
			var signOp = nfCrypto.sign({
				name: "HMAC",
				params: { hash: "SHA-256" }
			}, KEY, DATA);
			signOp.onerror = function (e) {
				error = "ERROR";
			};
			signOp.oncomplete = function (e) {
				signature = e.target.result;
			};
		});
		waitsFor(function () {
			return signature || error;
		});
		runs(function () {
			expect(error).toBeUndefined();
			expect(signature).toBeDefined();
		});
		runs(function () {
			var signOp = nfCrypto.verify({
				name: "SHA1",
				params: { hash: "SHA-256" }
			}, KEY, signature, data);
			signOp.onerror = function (e) {
				error = "ERROR";
			};
			signOp.oncomplete = function (e) {
				verified = e.target.result;
			};
		});
		waitsFor(function () {
			return verified || error;
		});

		runs(function () {
			expect(error).toBe("ERROR");
			expect(verified).toBeUndefined();
		});
	});//it("VerifyInvalidAlgoType")

	//Test for invalid signature
	it("InvalidSignature", function () {
		var error = undefined;
		var verified = undefined;
		var signature = undefined;

		runs(function () {
			var signOp = nfCrypto.sign({
				name: "HMAC",
				params: { hash: "SHA-256" }
			}, KEY, DATA);
			signOp.onerror = function (e) {
				error = "ERROR";
			};
			signOp.oncomplete = function (e) {
				signature = e.target.result;
			};
		});
		waitsFor(function () {
			return signature || error;
		});
		runs(function () {
			expect(error).toBeUndefined();
			expect(signature).toBeDefined();
		});
		runs(function () {
			signature[0] = signature[0] + 1;
			var signOp = nfCrypto.verify({
				name: "HMAC",
				params: { hash: "SHA-256" }
			}, KEY, signature, DATA);
			signOp.onerror = function (e) {
				error = "ERROR";
			};
			signOp.oncomplete = function (e) {
				verified = e.target.result;
			};
		});
		waitsFor(function () {
			return verified !== undefined || error;
		});

		runs(function () {
			expect(error).toBeUndefined();
			expect(verified).toBe(false);
		});
	});//it("InvalidSignature")

	//Test for invalid sign key
	it("InvalidSignKey", function () {
		var error = undefined;
		var verified = undefined;
		var signature = undefined;
		KEY.handle = 0;

		runs(function () {
			var signOp = nfCrypto.sign({
				name: "HMAC",
				params: { hash: "SHA-256" }
			}, KEY, DATA);
			signOp.onerror = function (e) {
				error = "ERROR";
			};
			signOp.oncomplete = function (e) {
				signature = e.target.result;
			};
		});
		waitsFor(function () {
			return signature || error;
		});
		runs(function () {
			expect(error).toBe("ERROR");
			expect(signature).toBeUndefined();
		});
	});//it("InvalidSignKey")

	//Test for invalid verify key
	it("InvalidVerifyKey", function () {
		var error = undefined;
		var verified = undefined;
		var signature = undefined;

		runs(function () {
			var signOp = nfCrypto.sign({
				name: "HMAC",
				params: { hash: "SHA-256" }
			}, KEY, DATA);
			signOp.onerror = function (e) {
				error = "ERROR";
			};
			signOp.oncomplete = function (e) {
				signature = e.target.result;
			};
		});
		waitsFor(function () {
			return signature || error;
		});
		runs(function () {
			expect(error).toBeUndefined();
			expect(signature).toBeDefined();
		});
		runs(function () {
			KEY.handle = 0
			var signOp = nfCrypto.verify({
				name: "HMAC",
				params: { hash: "SHA-256" }
			}, KEY, signature, DATA);
			signOp.onerror = function (e) {
				error = "ERROR";
			};
			signOp.oncomplete = function (e) {
				verified = e.target.result;
			};
		});
		waitsFor(function () {
			return verified !== undefined || error;
		});

		runs(function () {
			expect(error).toBe("ERROR");
			expect(verified).toBeUndefined();
		});
	});//it("InvalidVerifyKey")	




});//describe("SignVerifyHMAC")
