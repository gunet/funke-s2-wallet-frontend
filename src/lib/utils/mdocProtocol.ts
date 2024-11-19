export async function createSessionKey(rawPublic: ArrayBuffer, ephemeralKey: CryptoKeyPair) : Promise<CryptoKey> { 
	const importedVerifierPublicKey = await crypto.subtle.importKey(
		"raw",
		rawPublic,
		{
			name: "ECDH",
			namedCurve: "P-256",
		},
		true,
		[]
	);

	const sessionKey = await crypto.subtle.deriveKey(
		{
			name: "ECDH",
			public: importedVerifierPublicKey
		},
		ephemeralKey.privateKey,
		{
			name: "AES-GCM",
			length: 256,
		},
		false,
		["encrypt", "decrypt"]
	);

	return sessionKey;
}

export async function encryptMessage(sessionKey, plaintext) {
	const enc = new TextEncoder();
	const iv = crypto.getRandomValues(new Uint8Array(12));

	const ciphertext = await crypto.subtle.encrypt(
		{
			name: "AES-GCM",
			iv: iv
		},
		sessionKey,
		enc.encode(plaintext)
	);

	return { iv, ciphertext };
}

export async function decryptMessage(sessionKey, iv, ciphertext) {
	const dec = new TextDecoder();

	const plaintext = await crypto.subtle.decrypt(
		{
			name: "AES-GCM",
			iv: iv
		},
		sessionKey,
		ciphertext
	);

	return dec.decode(plaintext);
}

export function hexToUint8Array(hexString) {
	return Uint8Array.from(hexString.match(/.{1,2}/g).map((byte) => parseInt(byte, 16)));
}

export function uint8ArrayToBase64Url(array: any) {
	// Convert the Uint8Array to a binary string
	let binaryString = '';
	array.forEach((byte: any) => {
		binaryString += String.fromCharCode(byte);
	});

	// Convert the binary string to a Base64 string
	let base64String = btoa(binaryString);

	// Convert the Base64 string to Base64URL format
	let base64UrlString = base64String
		.replace(/\+/g, '-') // Replace + with -
		.replace(/\//g, '_') // Replace / with _
		.replace(/=+$/, ''); // Remove trailing '='

	return base64UrlString;
}

export async function deriveSKReader(sessionTranscriptBytes) {

}

/*
		Source: https://github.com/mdn/dom-examples/blob/main/web-crypto/derive-key/hkdf.js
    Derive a shared secret, given:
    - our ECDH private key
    - their ECDH public key
*/
export async function deriveSharedSecret(privateKey, publicKey) {
	const secret = await crypto.subtle.deriveBits(
		{ name: "ECDH", public: publicKey },
		privateKey,
		256
	);

	return crypto.subtle.importKey(
		"raw",
		secret,
		{ name: "HKDF" },
		false,
		["deriveKey"]
	);
}

export async function getKey(keyMaterial, salt, info) {
	return await crypto.subtle.deriveKey(
		{
			name: "HKDF",
			salt: salt,
			info: new TextEncoder().encode(info).buffer,
			hash: "SHA-256",
		},
		keyMaterial,
		{ name: "AES-GCM", length: 256 },
		true,
		["encrypt", "decrypt"]
	);
}