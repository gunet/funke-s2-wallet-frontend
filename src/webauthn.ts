import * as cbor from 'cbor-web';


export type ParsedCOSEKey = {
	kty: number | string,
	kid?: Uint8Array,
	alg?: COSEAlgorithmIdentifier,
	[name: string]: any,
};

export type ParsedCOSEKeyEc2Public = ParsedCOSEKey & {
	kty: 2,
	kid?: Uint8Array,
	alg?: COSEAlgorithmIdentifier,
	crv: number,
	x: Uint8Array,
	y: Uint8Array,
};

export type ParsedCOSEKeyArkgPubSeed = ParsedCOSEKey & {
	kty: -65537,
	pkBl: ParsedCOSEKey,
	pkKem: ParsedCOSEKey,
};

export type ParsedCOSEKeyRef = {
	kty: number | string,
	kid: Uint8Array,
	alg?: COSEAlgorithmIdentifier,
	[name: string]: any,
};

export type ParsedCOSEKeyRefArkgDerivedBase = ParsedCOSEKeyRef & {
	kty: -65538,
	kh: Uint8Array,
};

export type ParsedCOSEKeyRefArkgDerived = ParsedCOSEKeyRefArkgDerivedBase & {
	info: Uint8Array,
}


export function parseAuthenticatorData(bytes: Uint8Array): {
	rpIdHash: Uint8Array,
	flags: {
		UP: boolean,
		UV: boolean,
		BE: boolean,
		BS: boolean,
		AT: boolean,
		ED: boolean,
	},
	signCount: number,
	attestedCredentialData?: { aaguid: Uint8Array, credentialId: Uint8Array, credentialPublicKey: { [key: number]: any } },
	extensions?: { [extensionId: string]: any },
} {
	const rpIdHash = bytes.slice(0, 32);
	const flagsByte = bytes[32]; // eslint-disable-line prefer-destructuring
	const signCount = new DataView(bytes.buffer).getUint32(32 + 1, false);

	const flags = {
		UP: (flagsByte & 0x01) !== 0,
		UV: (flagsByte & 0x04) !== 0,
		BE: (flagsByte & 0x08) !== 0,
		BS: (flagsByte & 0x10) !== 0,
		AT: (flagsByte & 0x40) !== 0,
		ED: (flagsByte & 0x80) !== 0,
	};

	if (flags.AT) {
		const [attestedCredentialData, extensions] = parseAttestedCredentialData(bytes.slice(32 + 1 + 4));
		if (Boolean(extensions) !== flags.ED) {
			throw new Error(`Extensions (present: ${extensions !== null}) do not match ED flag (${flags.ED})`);
		}
		return {
			rpIdHash,
			flags,
			signCount,
			attestedCredentialData,
			...(extensions ? { extensions } : {}),
		};
	} else {
		if (flags.ED !== (bytes.length > 32 + 1 + 4)) {
			throw new Error(`Extensions (present: ${bytes.length > 32 + 1 + 4}) do not match ED flag (${flags.ED})`);
		}
		if (flags.ED) {
			const [extensions] = cbor.decodeAllSync(bytes.slice(32 + 1 + 4));
			return {
				rpIdHash,
				flags,
				signCount,
				extensions,
			};
		} else {
			return {
				rpIdHash,
				flags,
				signCount,
			};
		}
	}
}

function parseAttestedCredentialData(bytes: Uint8Array): [
	{ aaguid: Uint8Array, credentialId: Uint8Array, credentialPublicKey: { [key: number]: any } },
	{ [extensionId: string]: any }?
] {
	const aaguid = bytes.slice(0, 16);
	const credentialIdLength = new DataView(bytes.buffer).getUint16(16, false);
	const credentialId = bytes.slice(16 + 2, 16 + 2 + credentialIdLength);
	const [credentialPublicKey, extensions] = cbor.decodeAllSync(bytes.slice(16 + 2 + credentialIdLength));
	return [
		{
			aaguid,
			credentialId,
			credentialPublicKey,
		},
		extensions,
	];
}

export function getAuthenticatorExtensionOutputs(credential: PublicKeyCredential): { [extensionId: string]: any } {
	const authenticatorData = (
		"authenticatorData" in credential.response
			? credential.response.authenticatorData
			: ("attestationObject" in credential.response
				? cbor.decodeFirstSync(credential.response.attestationObject)["authData"]
				: null
			)
	);
	if (authenticatorData === null) {
		throw new Error(`Failed to get authenticator data from credential: ${credential}`, { cause: { credential } });
	}

	return parseAuthenticatorData(authenticatorData).extensions;
}

export async function importCosePublicKey(cose: cbor.Map): Promise<CryptoKey> {
	const coseKey = parseCoseKeyEc2Public(cose);
	const [algorithm, keyUsages] = getEcKeyImportParams(coseKey);
	const rawBytes = new Uint8Array([
		0x04,
		...new Uint8Array(Math.max(0, 32 - coseKey.x.length)),
		...coseKey.x,
		...new Uint8Array(Math.max(0, 32 - coseKey.y.length)),
		...coseKey.y,
	]);
	return await crypto.subtle.importKey("raw", rawBytes, algorithm, true, keyUsages);
}

function getEcKeyImportParams(cose: ParsedCOSEKeyEc2Public): [EcKeyImportParams, KeyUsage[]] {
	const { alg, crv } = cose;
	switch (alg) {
		case -7: // ES256
			switch (crv) {
				case 1: // P-256
					return [{ name: "ECDSA", namedCurve: "P-256" }, ["verify"]];
				default:
					throw new Error(`Unsupported COSE elliptic curve: ${crv}`, { cause: { crv } })
			}

		case -25: // ECDH-ES + HKDF-256
			switch (crv) {
				case 1: // P-256
					return [{ name: "ECDH", namedCurve: "P-256" }, ["deriveBits", "deriveKey"]];

				default:
					throw new Error(`Unsupported COSE elliptic curve: ${crv}`, { cause: { crv } })
			}

		default:
			throw new Error(`Unsupported COSE algorithm: ${alg}`, { cause: { alg } })
	}
}

export function parseCoseKeyEc2Public(cose: cbor.Map): ParsedCOSEKeyEc2Public {
	const kty = cose.get(1);
	switch (kty) {

		case 2: // EC2
			const alg = cose.get(3);
			switch (alg) {

				case -7: // ES256
				case -25: // ECDH-ES + HKDF-256
					const crv = cose.get(-1);
					switch (crv) {

						case 1: // P-256
							const x = cose.get(-2);
							const y = cose.get(-3);
							if (x && y) {
								if (!(x instanceof Uint8Array)) {
									throw new Error(
										`Incorrect type of "x (-2)" attribute of EC2 COSE_Key: ${typeof x} ${x}`,
										{ cause: { x } },
									);
								}
								if (!(y instanceof Uint8Array)) {
									throw new Error(
										`Incorrect type of "y (-3)" attribute of EC2 COSE_Key: ${typeof y} ${y}`,
										{ cause: { y } },
									);
								}
								return { kty, alg, crv, x, y };
							} else {
								throw new Error(`Invalid COSE EC2 ES256 or ECDH key: missing x or y`, { cause: { x, y } });
							}

						default:
							throw new Error(`Unsupported COSE elliptic curve: ${crv}`, { cause: { crv } })
					}

				default:
					throw new Error(`Unsupported COSE algorithm: ${alg}`, { cause: { alg } })
			}

		default:
			throw new Error(`Unsupported COSE key type: ${kty}`, { cause: { kty } });
	}
}

export function parseCoseKeyArkgPubSeed(cose: cbor.Map): ParsedCOSEKeyArkgPubSeed {
	const kty = cose.get(1);
	switch (kty) {

		case -65537: // ARKG-pub-seed https://yubico.github.io/arkg-rfc/draft-bradleylundberg-cfrg-arkg.html#name-cose-key-types-registration
			const pkBl = parseCoseKeyEc2Public(cose.get(-1));
			const pkKem = parseCoseKeyEc2Public(cose.get(-2));
			return { kty, pkBl, pkKem };

		default:
			throw new Error(`Unsupported COSE key type: ${kty}`, { cause: { kty } });
	}
}

export function parseCoseRefArkgDerivedBase(cose: cbor.Map): ParsedCOSEKeyRefArkgDerivedBase {
	const kid = cose.get(2);
	if (!(kid instanceof Uint8Array)) {
		throw new Error(
			`Incorrect type of "kid (2)" attribute of ARKG-derived COSE_Key_Ref: ${typeof kid} ${kid}`,
			{ cause: { kid } },
		);
	}

	const kty = cose.get(1);
	switch (kty) {

		case -65538: // ARKG-derived https://yubico.github.io/arkg-rfc/draft-bradleylundberg-cfrg-arkg.html#name-cose-key-types-registration
			const kh = cose.get(-1);
			if (!(kh instanceof Uint8Array)) {
				throw new Error(
					`Incorrect type of "kh (-1)" attribute of ARKG-derived COSE_Key_Ref: ${typeof kh} ${kh}`,
					{ cause: { kh } },
				);
			}
			return { kty, kid, kh };

		default:
			throw new Error(`Unsupported COSE_Key_Ref type: ${kty}`, { cause: { kty } });
	}
}
