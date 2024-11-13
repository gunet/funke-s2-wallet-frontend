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