/// Implementation of ARKG
/// https://datatracker.ietf.org/doc/draft-bradleylundberg-cfrg-arkg/06/

import * as ec from './ec';
import * as hash_to_curve from './hash_to_curve';
import { byteArrayEquals, concat, fromBase64Url, fromHex, toBase64, toHex, toU8 } from '../util';
import { COSE_ALG_ARKG_P256 as COSE_ALG_ARKG_P256 } from '../coseConstants';
import { ParsedCOSEKeyArkgPubSeed, ParsedCOSEKeyEc2Public } from '../webauthn';


const CTX_MAX_LEN = 64;

type DeriveKeypairFunction<PublicKey, PrivateKey> = (
	(ikm: BufferSource) => Promise<[PublicKey, PrivateKey]>
);

type KemEncapsFunction<PublicKey> = (
	(pubk: PublicKey, ikm: BufferSource, ctx: BufferSource) => Promise<[ArrayBuffer, ArrayBuffer]>
);
type KemDecapsFunction<PrivateKey> = (
	(prik: PrivateKey, c: BufferSource, ctx: BufferSource) => Promise<ArrayBuffer>
);
type KemScheme<PublicKey, PrivateKey> = {
	deriveKeypair: DeriveKeypairFunction<PublicKey, PrivateKey>,
	encaps: KemEncapsFunction<PublicKey>,
	decaps: KemDecapsFunction<PrivateKey>,
}

type BlBlindKeyFunction<BaseKey, BlindedKey> = (
	(key: BaseKey, tau: BufferSource, ctx: BufferSource) => Promise<BlindedKey>
);
type BlScheme<PublicKey, PrivateKey, DerivedPublicKey, DerivedPrivateKey> = {
	deriveKeypair: DeriveKeypairFunction<PublicKey, PrivateKey>,
	blindPublicKey: BlBlindKeyFunction<PublicKey, DerivedPublicKey>,
	blindPrivateKey: BlBlindKeyFunction<PrivateKey, DerivedPrivateKey>,
}

type ArkgPublicSeed<BlPublicKey, KemPublicKey> = {
	pubk_bl: BlPublicKey,
	pubk_kem: KemPublicKey,
}
type ArkgPrivateSeed<BlPrivateKey, KemPrivateKey> = {
	prik_bl: BlPrivateKey,
	prik_kem: KemPrivateKey,
}

type ArkgDeriveSeedFunction<BlPublicKey, BlPrivateKey, KemPublicKey, KemPrivateKey> = (
	(ikm_bl: BufferSource, ikm_kem: BufferSource) => Promise<[ArkgPublicSeed<BlPublicKey, KemPublicKey>, ArkgPrivateSeed<BlPrivateKey, KemPrivateKey>]>
);
type ArkgDerivePublicKeyFunction<BlPublicKey, KemPublicKey, DerivedPublicKey> = (
	(
		seed_pk: ArkgPublicSeed<BlPublicKey, KemPublicKey>,
		ikm: BufferSource,
		ctx: BufferSource,
	) => Promise<[DerivedPublicKey, ArrayBuffer]>
);
type ArkgDerivePrivateKeyFunction<BlPrivateKey, KemPrivateKey, DerivedPrivateKey> = (
	(
		seed_prik: ArkgPrivateSeed<BlPrivateKey, KemPrivateKey>,
		kh: BufferSource,
		ctx: BufferSource,
	) => Promise<DerivedPrivateKey>
);
type ArkgInstance<BlPublicKey, BlPrivateKey, KemPublicKey, KemPrivateKey, DerivedPublicKey, DerivedPrivateKey> = {
	/** @see https://yubico.github.io/arkg-rfc/draft-bradleylundberg-cfrg-arkg.html#name-the-function-arkg-generate- */
	deriveSeed: ArkgDeriveSeedFunction<BlPublicKey, BlPrivateKey, KemPublicKey, KemPrivateKey>,

	/** @see https://yubico.github.io/arkg-rfc/draft-bradleylundberg-cfrg-arkg.html#name-the-function-arkg-derive-pu */
	derivePublicKey: ArkgDerivePublicKeyFunction<BlPublicKey, KemPublicKey, DerivedPublicKey>,

	/** @see https://yubico.github.io/arkg-rfc/draft-bradleylundberg-cfrg-arkg.html#name-the-function-arkg-derive-pr */
	derivePrivateKey: ArkgDerivePrivateKeyFunction<BlPrivateKey, KemPrivateKey, DerivedPrivateKey>,
}


/** @see https://yubico.github.io/arkg-rfc/draft-bradleylundberg-cfrg-arkg.html#name-the-asynchronous-remote-key */
function arkg<BlPublicKey, BlPrivateKey, KemPublicKey, KemPrivateKey, DerivedPublicKey, DerivedPrivateKey>(
	bl: BlScheme<BlPublicKey, BlPrivateKey, DerivedPublicKey, DerivedPrivateKey>,
	kem: KemScheme<KemPublicKey, KemPrivateKey>,
): ArkgInstance<BlPublicKey, BlPrivateKey, KemPublicKey, KemPrivateKey, DerivedPublicKey, DerivedPrivateKey> {
	return {
		deriveSeed: async (ikm_bl: BufferSource, ikm_kem): Promise<[ArkgPublicSeed<BlPublicKey, KemPublicKey>, ArkgPrivateSeed<BlPrivateKey, KemPrivateKey>]> => {
			const [pubk_bl, prik_bl] = await bl.deriveKeypair(ikm_bl);
			const [pubk_kem, prik_kem] = await kem.deriveKeypair(ikm_kem);
			const pubk = { pubk_bl, pubk_kem };
			const prik = { prik_bl, prik_kem };
			return [pubk, prik];
		},

		derivePublicKey: async (
			{ pubk_bl, pubk_kem }: ArkgPublicSeed<BlPublicKey, KemPublicKey>,
			ikm: BufferSource,
			ctx: BufferSource,
		): Promise<[DerivedPublicKey, ArrayBuffer]> => {
			if (ctx.byteLength > CTX_MAX_LEN) {
				throw new Error("ctx too long", { cause: { ctx, maxLength: CTX_MAX_LEN } });
			}

			const ctx_kem = concat(new TextEncoder().encode('ARKG-Derive-Key-KEM.'), new Uint8Array([ctx.byteLength]), ctx);
			const ctx_bl = concat(new TextEncoder().encode('ARKG-Derive-Key-BL.'), new Uint8Array([ctx.byteLength]), ctx);
			const [tau, c] = await kem.encaps(pubk_kem, ikm, ctx_kem);
			const pk_prime = await bl.blindPublicKey(pubk_bl, tau, ctx_bl);
			const kh = c;
			return [pk_prime, kh];
		},

		derivePrivateKey: async (
			{ prik_bl, prik_kem }: ArkgPrivateSeed<BlPrivateKey, KemPrivateKey>,
			kh: BufferSource,
			ctx: BufferSource,
		): Promise<DerivedPrivateKey> => {
			if (ctx.byteLength > CTX_MAX_LEN) {
				throw new Error("ctx too long", { cause: { ctx, maxLength: CTX_MAX_LEN } });
			}

			const ctx_kem = concat(new TextEncoder().encode('ARKG-Derive-Key-KEM.'), new Uint8Array([ctx.byteLength]), ctx);
			const ctx_bl = concat(new TextEncoder().encode('ARKG-Derive-Key-BL.'), new Uint8Array([ctx.byteLength]), ctx);
			const tau = await kem.decaps(prik_kem, kh, ctx_kem);
			const sk_prime = await bl.blindPrivateKey(prik_bl, tau, ctx_bl);
			return sk_prime;
		}
	};
}

/** @see https://yubico.github.io/arkg-rfc/draft-bradleylundberg-cfrg-arkg.html#name-using-elliptic-curve-additi */
function arkgBlEcAdd(
	hashToCurveSuiteId: hash_to_curve.SuiteId,
	dst_ext: BufferSource,
): BlScheme<ec.Point, bigint, ec.Point, bigint> {
	const { suiteParams } = hash_to_curve.hashToCurve(hashToCurveSuiteId, concat(
		new TextEncoder().encode('ARKG-BL-EC.'),
		dst_ext,
	));
	const { curve: crv } = suiteParams;

	if (suiteParams.m !== 1) {
		throw new Error("Invalid argument: hash_to_crv_suite parameter m must equal 1");
	}

	return {
		deriveKeypair: async (ikm: BufferSource): Promise<[ec.Point, bigint]> => {
			const DST = concat(new TextEncoder().encode('ARKG-BL-EC-KG.'), dst_ext);
			const { hashToScalarField } = hash_to_curve.hashToCurve(hashToCurveSuiteId, DST);
			const [[sk]] = await hashToScalarField(ikm, 1);
			const pk = ec.vartimeMul(crv, crv.generator, sk);
			return [pk, sk];
		},

		blindPublicKey: async (pk: ec.Point, tau: BufferSource, ctx: BufferSource): Promise<ec.Point> => {
			const DST = concat(new TextEncoder().encode('ARKG-BL-EC.'), dst_ext, ctx);
			const { hashToScalarField } = hash_to_curve.hashToCurve(hashToCurveSuiteId, DST);
			const [[tau_prime]] = await hashToScalarField(tau, 1);
			const pk_tau = ec.vartimeAdd(crv, pk, ec.vartimeMul(crv, crv.generator, tau_prime));
			return pk_tau;
		},

		blindPrivateKey: async (prik: bigint, tau: BufferSource, ctx: BufferSource): Promise<bigint> => {
			const DST = concat(new TextEncoder().encode('ARKG-BL-EC.'), dst_ext, ctx);
			const { hashToScalarField } = hash_to_curve.hashToCurve(hashToCurveSuiteId, DST);
			const [[tau_prime]] = await hashToScalarField(tau, 1);
			const sk_tau_tmp = (prik + tau_prime) % crv.order;
			if (sk_tau_tmp === 0n) {
				throw new Error("Invalid secret key");
			}
			const sk_tau = sk_tau_tmp;
			return sk_tau;
		},
	};
}

/** @see https://yubico.github.io/arkg-rfc/draft-bradleylundberg-cfrg-arkg.html#name-using-hmac-to-adapt-a-kem-w */
function arkgHmacKem<PublicKey, PrivateKey>(
	hash: "SHA-256",
	dst_ext: BufferSource,
	SubKem: KemScheme<PublicKey, PrivateKey>,
): KemScheme<PublicKey, PrivateKey> {
	return {
		deriveKeypair: SubKem.deriveKeypair,

		encaps: async (pubk: PublicKey, ikm: BufferSource, ctx: BufferSource): Promise<[ArrayBuffer, ArrayBuffer]> => {
			const ctx_sub = concat(new TextEncoder().encode('ARKG-KEM-HMAC.'), dst_ext, ctx);
			const [k_prime, c_prime] = await SubKem.encaps(pubk, ikm, ctx_sub);

			const hkdf_ikm = await crypto.subtle.importKey("raw", k_prime, { name: "HKDF" }, false, ["deriveBits", "deriveKey"]);

			const mk = await crypto.subtle.deriveKey(
				{
					name: "HKDF",
					hash,
					salt: new Uint8Array([]),
					info: concat(new TextEncoder().encode('ARKG-KEM-HMAC-mac.'), dst_ext, ctx),
				},
				hkdf_ikm,
				{ name: "HMAC", hash, length: 32*8 },
				false,
				["sign"],
			);
			const t = toU8(await crypto.subtle.sign("HMAC", mk, c_prime)).slice(0, 16);

			const k = await crypto.subtle.deriveBits(
				{
					name: "HKDF",
					hash,
					salt: new Uint8Array([]),
					info: concat(new TextEncoder().encode('ARKG-KEM-HMAC-shared.'), dst_ext, ctx),
				},
				hkdf_ikm,
				k_prime.byteLength * 8,
			);
			const c = concat(t, c_prime);

			return [k, c];
		},

		decaps: async (prik: PrivateKey, c: BufferSource, ctx: BufferSource): Promise<ArrayBuffer> => {
			const c_u8 = toU8(c);
			const t = c_u8.slice(0, 16);
			const c_prime = c_u8.slice(16);
			const ctx_sub = concat(new TextEncoder().encode('ARKG-KEM-HMAC.'), dst_ext, ctx);
			const k_prime = await SubKem.decaps(prik, c_prime, ctx_sub);

			const ikm = await crypto.subtle.importKey("raw", k_prime, { name: "HKDF" }, false, ["deriveBits", "deriveKey"]);

			const mk = await crypto.subtle.deriveKey(
				{
					name: "HKDF",
					hash,
					salt: new Uint8Array([]),
					info: concat(new TextEncoder().encode('ARKG-KEM-HMAC-mac.'), dst_ext, ctx),
				},
				ikm,
				{ name: "HMAC", hash, length: 32*8 },
				false,
				["sign"],
			);

			const t_prime = new Uint8Array(await crypto.subtle.sign("HMAC", mk, c_prime)).slice(0, 16);
			if (byteArrayEquals(t, t_prime)) {
				const k = await crypto.subtle.deriveBits(
					{
						name: "HKDF",
						hash,
						salt: new Uint8Array([]),
						info: concat(new TextEncoder().encode('ARKG-KEM-HMAC-shared.'), dst_ext, ctx),
					},
					ikm,
					k_prime.byteLength * 8,
				);
				return k;

			} else {
				throw new Error("Invalid MAC");
			}
		},
	};
}

/** @see https://yubico.github.io/arkg-rfc/draft-bradleylundberg-cfrg-arkg.html#name-using-ecdh-as-the-kem */
function arkgEcdhKem(
	namedCurve: "P-256",
	hash: "SHA-256",
	hashToCurveSuiteId: hash_to_curve.SuiteId,
	dst_ext: BufferSource,
): KemScheme<CryptoKey, CryptoKey> {
	const [crv, L]: [ec.Curve, number] = (namedCurve === "P-256" ? [ec.curveSecp256r1(), 8 * 32] : [null, null]);
	if (crv === null) {
		throw new Error("Unknown curve: " + namedCurve);
	}

	const dst_aug = concat(new TextEncoder().encode('ARKG-ECDH.'), dst_ext);

	const deriveKeypair = async (ikm: BufferSource): Promise<[CryptoKey, CryptoKey]> => {
		const DST = concat(new TextEncoder().encode('ARKG-KEM-ECDH-KG.'), dst_aug);
		const { hashToScalarField } = hash_to_curve.hashToCurve(hashToCurveSuiteId, DST);
		const [[sk]] = await hashToScalarField(ikm, 1);
		const pk = ec.vartimeMul(crv, crv.generator, sk);
		return [
			await ec.publicKeyFromPoint("ECDH", namedCurve, pk),
			await ec.privateKeyFromScalar("ECDH", namedCurve, sk, true, ["deriveBits"]),
		];
	};

	return arkgHmacKem(hash, dst_aug, {
		deriveKeypair,

		encaps: async (pubk: CryptoKey, ikm: BufferSource, _ctx: BufferSource): Promise<[ArrayBuffer, ArrayBuffer]> => {
			const [pk_prime, sk_prime] = await deriveKeypair(ikm);
			const k = await crypto.subtle.deriveBits({ name: "ECDH", public: pubk }, sk_prime, L);
			const c = await crypto.subtle.exportKey("raw", pk_prime);
			return [k, c];
		},

		decaps: async (prik: CryptoKey, c: BufferSource, _ctx: BufferSource): Promise<ArrayBuffer> => {
			const pk_prime = await crypto.subtle.importKey("raw", c, { name: "ECDH", namedCurve }, true, []);
			const k = await crypto.subtle.deriveBits({ name: "ECDH", public: pk_prime }, prik, L);
			return k;
		},
	});
}

/**
	@see https://yubico.github.io/arkg-rfc/draft-bradleylundberg-cfrg-arkg.html#name-arkg-p256add-ecdh
	*/
export type EcInstanceId = (
	'ARKG-P256'
);

// Declare as factory functions instead of a global variable registry to prevent callers from overriding internal properties
const ecInstances: { [id in EcInstanceId]: () => ArkgInstance<ec.Point, bigint, CryptoKey, CryptoKey, ec.Point, bigint> } = {
	'ARKG-P256': () => arkg(
		arkgBlEcAdd("P256_XMD:SHA-256_SSWU_RO_", new TextEncoder().encode('ARKG-P256')),
		arkgEcdhKem("P-256", "SHA-256", "P256_XMD:SHA-256_SSWU_RO_", new TextEncoder().encode('ARKG-P256')),
	),
};

/**
	Instantiate an EC-based ARKG instance.

	@see https://yubico.github.io/arkg-rfc/draft-bradleylundberg-cfrg-arkg.html#name-concrete-arkg-instantiation
	*/
export function getEcInstance(id: EcInstanceId): ArkgInstance<ec.Point, bigint, CryptoKey, CryptoKey, ec.Point, bigint> {
	return ecInstances[id]();
}

export function coseToInstanceId(coseId: COSEAlgorithmIdentifier): EcInstanceId | null {
	switch (coseId) {
		case COSE_ALG_ARKG_P256:
			return 'ARKG-P256';
		default:
			return null;
	}
}

export function getCoseEcInstance(coseId: COSEAlgorithmIdentifier): ArkgInstance<ec.Point, bigint, CryptoKey, CryptoKey, ec.Point, bigint> | null {
	const id = coseToInstanceId(coseId);
	return id ? getEcInstance(id) : null;
}

export async function ecPublicKeyFromCose(pk: ParsedCOSEKeyArkgPubSeed): Promise<ArkgPublicSeed<ec.Point, CryptoKey>> {
	switch (pk.alg) {
		case COSE_ALG_ARKG_P256:
			const crv = ec.curveSecp256r1();
			return {
				pubk_bl: await ec.pointFromCosePublicKey(crv, pk.pkBl as ParsedCOSEKeyEc2Public),
				pubk_kem: await ec.publicKeyFromPoint("ECDH", "P-256", await ec.pointFromCosePublicKey(crv, pk.pkKem as ParsedCOSEKeyEc2Public)),
			};

		default:
			throw new Error("Unsupported ARKG algorithm for COSE identifier: " + pk.alg);
	}
}


import { assert, describe, it } from "vitest"; // eslint-disable-line import/first
import { asyncAssertThrows } from '../testutil'; // eslint-disable-line import/first
import { bigIntToBinary } from './util';

export function tests() {

	describe("Assumptions:", async () => {
		it("In WebCrypto, empty HKDF salt is equivalent to no salt (interpreted as hashLen zeros)", async () => {
			const key0 = await crypto.subtle.generateKey({ name: "HMAC", hash: "SHA-256" }, true, ["sign"]);
			const keyx = await crypto.subtle.exportKey("raw", key0);
			const key = await crypto.subtle.importKey("raw", keyx, "HKDF", false, ["deriveBits"]);
			const zeroes32 = new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
			assert.equal(zeroes32.length, 32);
			const okm1 = await crypto.subtle.deriveBits(
				{
					name: "HKDF",
					hash: "SHA-256",
					salt: new Uint8Array([]),
					info: new TextEncoder().encode("assumption test"),
				},
				key,
				64 * 8,
			);
			const okm2 = await crypto.subtle.deriveBits(
				{
					name: "HKDF",
					hash: "SHA-256",
					salt: zeroes32,
					info: new TextEncoder().encode("assumption test"),
				},
				key,
				64 * 8,
			);
			assert.isTrue(byteArrayEquals(okm1, okm2));
		});
	});

	describe("ARKG", async () => {
		const instances: {
			instanceName: EcInstanceId,
			namedCurve: "P-256",
			signAlgorithm: EcdsaParams,
			crv: ec.Curve,
		}[] = [
				{
					instanceName: "ARKG-P256",
					namedCurve: "P-256",
					signAlgorithm: { name: "ECDSA", hash: "SHA-256" },
					crv: ec.curveSecp256r1(),
				},
			];
		for (const { instanceName, namedCurve, signAlgorithm, crv } of instances) {
			const arkgInstance = getEcInstance(instanceName);

			describe(`instance ${instanceName}`, async () => {

				const ikm_bl = crypto.getRandomValues(new Uint8Array(32));
				const ikm_kem = crypto.getRandomValues(new Uint8Array(32));
				const ikm = crypto.getRandomValues(new Uint8Array(32));

				const ikm_bl_1 = ikm_bl;
				const ikm_bl_2 = crypto.getRandomValues(new Uint8Array(32));
				const ikm_kem_1 = ikm_kem;
				const ikm_kem_2 = crypto.getRandomValues(new Uint8Array(32));
				const ikm_1 = ikm;
				const ikm_2 = crypto.getRandomValues(new Uint8Array(32));

				const [pub_seed, pri_seed] = await arkgInstance.deriveSeed(ikm_bl, ikm_kem);

				const ctx = new TextEncoder().encode(instanceName + "test vectors");
				const [derived_pubk, kh] = await arkgInstance.derivePublicKey(pub_seed, ikm, ctx);

				it("forbids ctx values longer than 64 bytes.", async () => {
					const ctx = crypto.getRandomValues(new Uint8Array(65));
					const [derived_pubk, kh] = await arkgInstance.derivePublicKey(pub_seed, ikm, ctx.slice(0, 64));
					assert.deepEqual(
						(await asyncAssertThrows(
							async () => await arkgInstance.derivePublicKey(pub_seed, ikm, ctx),
							"Expected derivePublicKey to fail with ctx longer than 64 bytes",
						) as any).cause,
						{ ctx, maxLength: 64 },
					);

					const derived_prik = await arkgInstance.derivePrivateKey(pri_seed, kh, ctx.slice(0, 64));
					assert.deepEqual(
						(await asyncAssertThrows(
							async () => await arkgInstance.derivePrivateKey(pri_seed, kh, ctx),
							"Expected derivePublicKey to fail with ctx longer than 64 bytes",
						) as any).cause,
						{ ctx, maxLength: 64 },
					);

					const publicKey = await ec.publicKeyFromPoint(signAlgorithm.name, namedCurve, derived_pubk);
					const privateKey = await ec.privateKeyFromScalar(signAlgorithm.name, namedCurve, derived_prik, false, ["sign"]);
					const sig = await crypto.subtle.sign(signAlgorithm, privateKey, ctx);
					const valid = await crypto.subtle.verify(signAlgorithm, publicKey, sig, concat(ctx));
					assert.isTrue(valid, "Invalid signature");
				});

				it.skip("test vector generation", async () => {
					for (const ctx_suffix of [".test vectors", ".test vectors.0", ".test vectors.1"]) {
						for (const ikmHex of ["404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f", "00"]) {
							const ikm_bl = fromHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
							const ikm_kem = fromHex("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
							const ikm = fromHex(ikmHex);

							const [pub_seed, pri_seed] = await arkgInstance.deriveSeed(ikm_bl, ikm_kem);
							const ctx_text = instanceName + ctx_suffix;
							const ctx = new TextEncoder().encode(ctx_text);
							const [derived_pubk, kh] = await arkgInstance.derivePublicKey(pub_seed, ikm, ctx);
							const derived_prik = await arkgInstance.derivePrivateKey(pri_seed, kh, ctx);
							const publicKey = await ec.publicKeyFromPoint(signAlgorithm.name, namedCurve, derived_pubk);
							const privateKey = await ec.privateKeyFromScalar(signAlgorithm.name, namedCurve, derived_prik, false, ["sign"]);
							const sig = await crypto.subtle.sign(signAlgorithm, privateKey, ctx);

							console.log("; Inputs:");
							console.log(`ctx      = '${ctx_text}'`);
							console.log(`ikm_bl   = h'${toHex(ikm_bl)}'`);
							console.log(`ikm_kem  = h'${toHex(ikm_kem)}'`);
							console.log(`ikm      = h'${toHex(ikm)}'`);
							console.log();

							console.log("; Derive-Seed outputs:");
							console.log(`pk_bl    = h'${toHex(toU8(await crypto.subtle.exportKey("raw", await ec.publicKeyFromPoint("ECDSA", "P-256", pub_seed.pubk_bl))))}'`);
							console.log(`pk_kem   = h'${toHex(toU8(await crypto.subtle.exportKey("raw", pub_seed.pubk_kem)))}'`);
							console.log(`sk_bl    = 0x${toHex(bigIntToBinary(pri_seed.prik_bl, 32))}`);
							console.log(`sk_kem   = 0x${toHex(fromBase64Url((await crypto.subtle.exportKey("jwk", pri_seed.prik_kem)).d))}`);
							console.log();

							console.log("; Derive-Public-Key outputs:");
							console.log(`pk_prime = h'${toHex(toU8(await crypto.subtle.exportKey("raw", await ec.publicKeyFromPoint("ECDSA", "P-256", derived_pubk))))}'`);
							console.log(`;kh      = (implementation defined)`);
							console.log();

							console.log("; Derive-Private-Key outputs:");
							console.log(`sk_prime = 0x${toHex(bigIntToBinary(derived_prik, 32))}`);
						}
					}

					assert.isTrue(false, "Forced failure");
				});

				it("is correct.", async () => {
					const derived_prik = await arkgInstance.derivePrivateKey(pri_seed, kh, ctx);
					const publicKey = await ec.publicKeyFromPoint(signAlgorithm.name, namedCurve, derived_pubk);
					const privateKey = await ec.privateKeyFromScalar(signAlgorithm.name, namedCurve, derived_prik, false, ["sign"]);
					const sig = await crypto.subtle.sign(signAlgorithm, privateKey, ctx);
					const valid = await crypto.subtle.verify(signAlgorithm, publicKey, sig, concat(ctx));
					assert.isTrue(valid, "Invalid signature");
				});

				describe("deriveSeed", () => {
					it("derives the same results on repeat calls.", async () => {
						const [pub_seed_1, pri_seed_1] = [pub_seed, pri_seed];
						const [pub_seed_2, pri_seed_2] = await arkgInstance.deriveSeed(ikm_bl, ikm_kem);
						assert.deepEqual(pub_seed_1, pub_seed_2);
						assert.deepEqual(pri_seed_1, pri_seed_2);
					});

					it("derives different results on calls with different ikm.", async () => {
						const [pub_seed_1, pri_seed_1] = [pub_seed, pri_seed];
						const [pub_seed_2, pri_seed_2] = await arkgInstance.deriveSeed(ikm_bl_2, ikm_kem_2);
						assert.notDeepEqual(pub_seed_1, pub_seed_2);
						assert.notDeepEqual(pri_seed_1, pri_seed_2);
					});
				});

				describe("derivePublicKey", () => {
					it("derives the same results on repeat calls.", async () => {
						const [derived_pubk_1, kh_1] = await arkgInstance.derivePublicKey(pub_seed, ikm, ctx);
						const [derived_pubk_2, kh_2] = await arkgInstance.derivePublicKey(pub_seed, ikm, ctx);
						assert.deepEqual(derived_pubk_1, derived_pubk_2);
						assert.deepEqual(toBase64(kh_1), toBase64(kh_2));
					});

					it("derives different results on calls with different ikm.", async () => {
						const [derived_pubk_1, kh_1] = await arkgInstance.derivePublicKey(pub_seed, ikm_1, ctx);
						const [derived_pubk_2, kh_2] = await arkgInstance.derivePublicKey(pub_seed, ikm_2, ctx);
						assert.notDeepEqual(derived_pubk_1, derived_pubk_2);
						assert.notDeepEqual(toBase64(kh_1), toBase64(kh_2));
					});
				});

				describe("derivePrivateKey", () => {
					it("derives the same result on repeat calls.", async () => {
						const derived_prik_1 = await arkgInstance.derivePrivateKey(pri_seed, kh, ctx);
						const derived_prik_2 = await arkgInstance.derivePrivateKey(pri_seed, kh, ctx);
						assert.equal(derived_prik_1, derived_prik_2);
					});

					it("fails if any bit of the key handle is modified.", async () => {
						const kh_u8 = new Uint8Array(kh);
						for (let i = 0; i < kh.byteLength * 8; ++i) {
							const kh_mod = new Uint8Array([...kh_u8]);
							const byte_i = Math.floor(i / 8);
							const bit_i = i % 8;
							kh_mod[byte_i] = kh_mod[byte_i] ^ (0x01 << bit_i);
							await asyncAssertThrows(
								async () => await arkgInstance.derivePrivateKey(pri_seed, kh_mod, ctx),
								`Expected key handle modified at bit index ${bit_i} of byte index ${byte_i} to fail. Unmodified: ${toHex(kh)}; modified: ${toHex(kh_mod)}`,
							);
						}
					});

					it("derives the wrong private key if any bit of the key handle is modified.", async () => {
						const kh_u8 = new Uint8Array(kh);
						for (let i = 0; i < kh.byteLength * 8; ++i) {
							const kh_mod = new Uint8Array([...kh_u8]);
							const byte_i = Math.floor(i / 8);
							const bit_i = i % 8;
							kh_mod[byte_i] = kh_mod[byte_i] ^ (0x01 << bit_i);
							await asyncAssertThrows(
								async () => {
									const derived_prik = await arkgInstance.derivePrivateKey(pri_seed, kh_mod, ctx)
									const publicKey = await ec.publicKeyFromPoint(signAlgorithm.name, namedCurve, derived_pubk);
									const privateKey = await ec.privateKeyFromScalar(signAlgorithm.name, namedCurve, derived_prik, false, ["sign"]);
									const sig = await crypto.subtle.sign(signAlgorithm, privateKey, ctx);
									const valid = await crypto.subtle.verify(signAlgorithm, publicKey, sig, concat(ctx));
									assert.isFalse(valid, "Unexpected valid signature");
								},
								`Expected key handle modified at bit index ${bit_i} of byte index ${byte_i} to result in the wrong private key. Unmodified: ${toHex(kh)}; modified: ${toHex(kh_mod)}`,
							);
						}
					}, { timeout: 60000 });

					describe("passes test vectors:", async () => {
						async function runTestVector(
							ctx: string,
							ikmBlHex: string,
							ikmKemHex: string,
							ikmHex: string,
							expectPkBlRawHex: string,
							expectPkKemRawHex: string,
							expectSkBlHex: string,
							expectSkKemHex: string,
							expectDerivedPkRawHex: string,
							expectDerivedSkHex: string,
						) {
							it(`${ctx}, ${ikmHex.substring(0, 8)}`, async () => {
								const ctxBytes = new TextEncoder().encode(ctx);
								const arkgInstance = getEcInstance('ARKG-P256');

								const [seed_pk, seed_sk] = await arkgInstance.deriveSeed(fromHex(ikmBlHex), fromHex(ikmKemHex));
								assert.deepEqual(seed_pk.pubk_bl, await ec.pointFromRaw(crv, fromHex(expectPkBlRawHex)));
								assert.deepEqual(
									await ec.pointFromPublicKey(crv, seed_pk.pubk_kem),
									await ec.pointFromRaw(crv, fromHex(expectPkKemRawHex)),
								);
								assert.deepEqual(seed_sk.prik_bl, BigInt("0x" + expectSkBlHex));
								assert.deepEqual(await ec.scalarFromPrivateKey(seed_sk.prik_kem), BigInt("0x" + expectSkKemHex));

								const [derivedPubKey, kh] = await arkgInstance.derivePublicKey(seed_pk, fromHex(ikmHex), ctxBytes);
								assert.deepEqual(derivedPubKey, await ec.pointFromRaw(crv, fromHex(expectDerivedPkRawHex)));

								const derivedPrivateKey = await arkgInstance.derivePrivateKey(seed_sk, kh, ctxBytes);
								assert.equal(
									derivedPrivateKey,
									BigInt("0x" + expectDerivedSkHex),
								);
							});
						}

						await runTestVector(
							"ARKG-P256.test vectors",
							"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
							"202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
							"404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
							"046d3bdf31d0db48988f16d47048fdd24123cd286e42d0512daa9f726b4ecf18df65ed42169c69675f936ff7de5f9bd93adbc8ea73036b16e8d90adbfabdaddba7",
							"04c38bbdd7286196733fa177e43b73cfd3d6d72cd11cc0bb2c9236cf85a42dcff5dfa339c1e07dfcdfda8d7be2a5a3c7382991f387dfe332b1dd8da6e0622cfb35",
							"d959500a78ccf850ce46c80a8c5043c9a2e33844232b3829df37d05b3069f455",
							"74e0a4cd81ca2d24246ff75bfd6d4fb7f9dfc938372627feb2c2348f8b1493b5",
							"04572a111ce5cfd2a67d56a0f7c684184b16ccd212490dc9c5b579df749647d107dac2a1b197cc10d2376559ad6df6bc107318d5cfb90def9f4a1f5347e086c2cd",
							"775d7fe9a6dfba43ce671cb38afca3d272c4d14aff97bd67559eb500a092e5e7",
						);
						await runTestVector(
							"ARKG-P256.test vectors",
							"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
							"202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
							"00",
							"046d3bdf31d0db48988f16d47048fdd24123cd286e42d0512daa9f726b4ecf18df65ed42169c69675f936ff7de5f9bd93adbc8ea73036b16e8d90adbfabdaddba7",
							"04c38bbdd7286196733fa177e43b73cfd3d6d72cd11cc0bb2c9236cf85a42dcff5dfa339c1e07dfcdfda8d7be2a5a3c7382991f387dfe332b1dd8da6e0622cfb35",
							"d959500a78ccf850ce46c80a8c5043c9a2e33844232b3829df37d05b3069f455",
							"74e0a4cd81ca2d24246ff75bfd6d4fb7f9dfc938372627feb2c2348f8b1493b5",
							"040e983f44cafa9036066857d1831b58cc2227677489df07d1ae0801259ddc0a6aa77f98712ecf662773ef73b6414d752bab57288cdce1299f73e606306bf77c54",
							"298271791090c1a0f3ef346a974b8daeab2876f2943207b2cddfe4ddff7a6295",
						);
						await runTestVector(
							"ARKG-P256.test vectors.0",
							"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
							"202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
							"404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
							"046d3bdf31d0db48988f16d47048fdd24123cd286e42d0512daa9f726b4ecf18df65ed42169c69675f936ff7de5f9bd93adbc8ea73036b16e8d90adbfabdaddba7",
							"04c38bbdd7286196733fa177e43b73cfd3d6d72cd11cc0bb2c9236cf85a42dcff5dfa339c1e07dfcdfda8d7be2a5a3c7382991f387dfe332b1dd8da6e0622cfb35",
							"d959500a78ccf850ce46c80a8c5043c9a2e33844232b3829df37d05b3069f455",
							"74e0a4cd81ca2d24246ff75bfd6d4fb7f9dfc938372627feb2c2348f8b1493b5",
							"04b79b65d6bbb419ff97006a1bd52e3f4ad53042173992423e06e52987a037cb61dd82b126b162e4e7e8dc5c9fd86e82769d402a1968c7c547ef53ae4f96e10b0e",
							"2a97f4232f9abba32fbfc28c6686f8afd2d851c2a95a3ed2f0a384b9ad55068d",
						);
						await runTestVector(
							"ARKG-P256.test vectors.0",
							"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
							"202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
							"00",
							"046d3bdf31d0db48988f16d47048fdd24123cd286e42d0512daa9f726b4ecf18df65ed42169c69675f936ff7de5f9bd93adbc8ea73036b16e8d90adbfabdaddba7",
							"04c38bbdd7286196733fa177e43b73cfd3d6d72cd11cc0bb2c9236cf85a42dcff5dfa339c1e07dfcdfda8d7be2a5a3c7382991f387dfe332b1dd8da6e0622cfb35",
							"d959500a78ccf850ce46c80a8c5043c9a2e33844232b3829df37d05b3069f455",
							"74e0a4cd81ca2d24246ff75bfd6d4fb7f9dfc938372627feb2c2348f8b1493b5",
							"04dfd47f9357efc0146e243c2cab4601c250b792111d6a364587a728d5624cfaf16e62dbf37ebc132537038f5daa2ff6cd38f229fd3063c618b4333cea35af6e85",
							"e5e0fab3367300dc45904128a3f8991a9d9059b585aac29e6f4e7cb45f59fce0",
						);
						await runTestVector(
							"ARKG-P256.test vectors.1",
							"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
							"202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
							"404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
							"046d3bdf31d0db48988f16d47048fdd24123cd286e42d0512daa9f726b4ecf18df65ed42169c69675f936ff7de5f9bd93adbc8ea73036b16e8d90adbfabdaddba7",
							"04c38bbdd7286196733fa177e43b73cfd3d6d72cd11cc0bb2c9236cf85a42dcff5dfa339c1e07dfcdfda8d7be2a5a3c7382991f387dfe332b1dd8da6e0622cfb35",
							"d959500a78ccf850ce46c80a8c5043c9a2e33844232b3829df37d05b3069f455",
							"74e0a4cd81ca2d24246ff75bfd6d4fb7f9dfc938372627feb2c2348f8b1493b5",
							"04cc85763fae2c8f38964ddc1f3dd9eebe2d2cb5c2842b0a622939b608f9cef967aafa50b9b24d6ae5a273f5b5d03b6a1ce8abd4f4dbaf487c417ef7380d1481b5",
							"1a60b7fe69b315fe1262c46711af990d47228471ef5a296f6aa26ba6a5a1a6ec",
						);
						await runTestVector(
							"ARKG-P256.test vectors.1",
							"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
							"202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
							"00",
							"046d3bdf31d0db48988f16d47048fdd24123cd286e42d0512daa9f726b4ecf18df65ed42169c69675f936ff7de5f9bd93adbc8ea73036b16e8d90adbfabdaddba7",
							"04c38bbdd7286196733fa177e43b73cfd3d6d72cd11cc0bb2c9236cf85a42dcff5dfa339c1e07dfcdfda8d7be2a5a3c7382991f387dfe332b1dd8da6e0622cfb35",
							"d959500a78ccf850ce46c80a8c5043c9a2e33844232b3829df37d05b3069f455",
							"74e0a4cd81ca2d24246ff75bfd6d4fb7f9dfc938372627feb2c2348f8b1493b5",
							"04056c654c97ea460ebfae997c8e12314184e45183aefdb8ce9547afca1faaee70da6c6433c8fe71c32284cf0a015eb463ea2fc81438f6698684525f011d7ae83c",
							"bb609831741d9232ecd7d58770c503992ca78d34361a865a0d6715861955526f",
						);
					});
				});
			});
		}
	});
}
