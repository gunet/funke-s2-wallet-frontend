import { assert, describe, it } from "vitest";
import { createSessionKey, encryptMessage, decryptMessage, hexToUint8Array } from "../utils/mdocProtocol";
import { cborDecode, cborEncode } from "../utils/cbor";

it("can decrypt a message with a session key", async () => {
	const keyPair = await crypto.subtle.generateKey(
		{
			name: "ECDH",
			namedCurve: "P-256", // the named curve for P-256
		},
		true, // whether the key is extractable (e.g., can be exported)
		["deriveKey"] // can be used for signing and verification
	);
	const ephemeralKey = keyPair;
	const verifierKeypair = await crypto.subtle.generateKey(
		{
			name: "ECDH",
			namedCurve: "P-256",
		},
		true,
		["deriveKey"]
	);
	const walletRawPubkey = await crypto.subtle.exportKey("raw", ephemeralKey.publicKey);
	const importedWalletKey = await crypto.subtle.importKey(
		"raw",
		walletRawPubkey,
		{
			name: "ECDH",
			namedCurve: "P-256",
		},
		true,
		[]
	);
	const verifierSessionKey = await crypto.subtle.deriveKey(
		{
			name: "ECDH",
			public: importedWalletKey
		},
		verifierKeypair.privateKey,
		{
			name: "AES-GCM",
			length: 256,
		},
		false,
		["encrypt", "decrypt"]
	);
	/* ---------------------------------------------------------- */
	const verifierRawPubkey = await crypto.subtle.exportKey("raw", verifierKeypair.publicKey);

	const walletSessionKey = await createSessionKey(verifierRawPubkey, ephemeralKey);


	console.log("SESSION KEY:");
	console.log(walletSessionKey);
	const msg = "sewqew12e21ew2§w§2w2§w21w§2w§2w§2w12!weqeqe12e123123213321123";
	const { iv, ciphertext } = await encryptMessage(verifierSessionKey, msg);

	const decryptedText = await decryptMessage(walletSessionKey, iv, ciphertext);
	console.log(decryptedText);

	assert.strictEqual(decryptedText, msg);
})