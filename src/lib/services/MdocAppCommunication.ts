import { IMdocAppCommunication } from "../interfaces/IMdocAppCommunication";
import { DataItem, MDoc } from "@auth0/mdl";
import { cborDecode, cborEncode } from "../utils/cbor";
import { v4 as uuidv4 } from 'uuid';
import { createSessionKey, encryptMessage, decryptMessage, hexToUint8Array, uint8ArrayToBase64Url, deriveSharedSecret, getKey, uint8ArraytoHexString, getSessionTranscriptBytes, getDeviceEngagement } from "../utils/mdocProtocol";
import { startBLE } from "../utils/ble"; 

export class MdocAppCommunication implements IMdocAppCommunication {
	constructor(
		private generateDeviceResponseFn: (mdocCredential: MDoc, presentationDefinition: any, sessionTranscripBytes: any) => Promise<{ deviceResponseMDoc: MDoc }>,
	) { }

	ephemeralKey: CryptoKeyPair;
	
	async generateEngagementQR() {
		console.log("Hello Engagement QR");

		const keyPair = await crypto.subtle.generateKey(
			{
				name: "ECDH",
				namedCurve: "P-256", // the named curve for P-256
			},
			true, // whether the key is extractable (e.g., can be exported)
			["deriveKey", "deriveBits"] // can be used for signing and verification
		);
		console.log("KEY PAIR...");
		console.log(keyPair);

		this.ephemeralKey = keyPair;

		console.log(keyPair.publicKey);
		const publicKeyJWK = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
		console.log(publicKeyJWK);


		// const uuid = uuidv4()
		const uuid =  '00179c7a-eec6-4f88-8646-045fda9ac4d8'
		
		const deviceEngagement = getDeviceEngagement(uuid, publicKeyJWK);

		const cbor = cborEncode(deviceEngagement);

		console.log(cbor);

		console.log(uint8ArraytoHexString(cbor));

		console.log(uint8ArrayToBase64Url(cbor));
		
		this.communicationSubphase(uuid, DataItem.fromData(deviceEngagement));
		return `mdoc:${uint8ArrayToBase64Url(cbor)}`;
	}

	async communicationSubphase(uuid: string, deviceEngagementBytes: any): Promise<void> {
		// alert('hi');
		let aggregatedData = [];
		/* @ts-ignore */
		if (window.nativeWrapper) {
			console.log("Found wrapper");
			/* @ts-ignore */
			const client = await window.nativeWrapper.bluetoothCreateClient(uuid);
			if (client) {
				console.log("Created BLE client");
				try {
					let dataReceived = [1];
					while(dataReceived[0] === 1) {
						/* @ts-ignore */
						dataReceived = JSON.parse(await window.nativeWrapper.bluetoothReceiveFromServer());
						console.log("Data received");
						console.log(dataReceived);
						aggregatedData = [...aggregatedData, ...dataReceived.slice(1)];
						console.log(dataReceived[0]);
					}
				} catch(e) {
					console.log("Error receiving");
					console.log(e);
				}
			}
		}
		console.log(aggregatedData);
		// const sessionMessage = await new Promise((resolve) => {
		// 	let result;
		// 	setTimeout(() => {
		// 		result = window.prompt("Session Message");
		// 		resolve(result);
		// 	}, 1000); // 1-second delay
		// });
		// const mdocRequest = await startBLE(uuid);
		console.log("🙏🙏");
		// console.log(mdocRequest);
		// const sessionMessage = mdocRequest;
		// const sessionMessage = "a26a655265616465724b6579d818584ba401022001215820b4f26059cb0ba6337b78636c003317fb8f7aee9cc91dab7f219829f34adb2bdc225820f48df8ed4351ca4ff59611e2def99b53e9763d388145a4f494a6466c824cb45864646174615902b1cc02d17f4a5e06bf4f5fa3d6c14635a54633c6a0a608bd859823b42039ff9018ddb97c8f58afbb5fe4c74190eb73611820ae8be9cdf56c115cbfac96614f7c92d6f21c302905fe5a3a84cdcf6544107cc1a73d377c7510ac25c4c9ebbe42c9999c4436db40b39e9629525783e8f00a0a21fec618ad273b87aca92af5b4e803b212c47a6318ca3bf727e3ff3d601c059916a39c2a10bfda4a0d1464ab02009d9918e4dcd8cca78acddc3566ce5d2a990199a5e8d469070b27f80639d20a0901e1e7e2910b343040fe27a2d508d682f17d32baebef8bbfbf25f8cce1413fbfd03b2b0dfadb4029434816ab6fc7157fdf4266f70bc3b3fffa34a946574bc162b6e21171bce7a78ad772b2b04d5081f2042bfb4940428d9a08c6b75f6caad23784b41f54793629fdef4d3bb12627e031f50c9f8c3478c0d16a3198d8cc38b856ce04b963322b99b82f591970cabcfc04a9c20353e4dcee047e438a2c28bac7807f4910a908731c6d4f7feec31a1a104c3afa46d6476d5f076cade81356529b8dad7ef0894e0793579351505e16246235c5ba8a2884c3594241034289c8d2bdfaecc8127fcf88145c5b3dfbea036c3d4cc36339a5390e8f2a8cd46db20887a5dfa0c8eaafc61958645ce2cdd9c24ad2e1a087c606c36733f906ec3b6b3d1a67524cc0b8ee977d8c6192fbe11bea6f040e665b5e1df6adb1fa0e6d2bccb68b0c3fdcc2cace93a25777a5c3d0b6c7bc77f3109b8639b95636561a48e0a08ff1c5cdcc30b78ce4dbc2d4ea3785c964738a22d39a58d5c0a59bc5f882be127283bfcaf36618707db5827896cb49ce1be028154335a283605e9291eeb339366ddf3e067ab0fd64a75c5756916e370ebc28c6b9a3310f478e5200c2d0b1a9f23ed0739f435fc888955a78a04ab80c4a1e0a3fabc6d56bf52a6a0983975f74611a3f8adcf12b74afe71a4ab997a48ac4c29348de07dc6e";
		const sessionMessage = uint8ArraytoHexString(new Uint8Array(aggregatedData));
		console.log("Session ✉");
		console.log(sessionMessage);
		const decoded = cborDecode(hexToUint8Array(sessionMessage));
		console.log(decoded);
		const readerKey = decoded.get('eReaderKey');
		const verifierData = decoded.get('data');
		console.log(new Uint8Array(readerKey.buffer));
		console.log(uint8ArrayToBase64Url(new Uint8Array(readerKey.buffer)));
		const coseKey = cborDecode(new Uint8Array(readerKey.buffer));
		console.log(coseKey);
		const verifierJWK = {
			kty: "EC",
			alg: "ECDH",
			crv: "P-256",
			x: uint8ArrayToBase64Url(coseKey.get(-2)),
			y: uint8ArrayToBase64Url(coseKey.get(-3))
		}
		console.log(verifierJWK);
		const verifierPublicKey = await crypto.subtle.importKey("jwk", verifierJWK, {name: "ECDH", namedCurve: "P-256"}, true, []);
		const rawVerifierPublicKey = await crypto.subtle.exportKey("raw", verifierPublicKey);
		console.log(rawVerifierPublicKey);
		// const sessionKey = await createSessionKey(rawVerifierPublicKey, this.ephemeralKey);
		const sessionKey = await crypto.subtle.deriveKey(
			{
				name: "ECDH",
				public: verifierPublicKey
			},
			this.ephemeralKey.privateKey,
			{
				name: "AES-GCM",
				length: 256,
			},
			false,
			["encrypt", "decrypt"]
		);
		console.log(sessionKey);
		console.log("--");
		console.log(verifierData);
		const sessionTranscriptBytes = getSessionTranscriptBytes(
			deviceEngagementBytes, // DeviceEngagementBytes
			decoded.get('eReaderKey'), // EReaderKeyBytes
		);
		console.log("Session Transcript Bytes");
		console.log(sessionTranscriptBytes);
		console.log(uint8ArraytoHexString(sessionTranscriptBytes));

		const zab = await deriveSharedSecret(this.ephemeralKey.privateKey, verifierPublicKey);
		const salt = await crypto.subtle.digest("SHA-256", sessionTranscriptBytes);
		console.log("SALT:");
		console.log(salt);
		const SKDevice = await getKey(zab, salt, "SKDevice");
		const SKReader = await getKey(zab, salt, "SKReader");
		console.log(zab);
		console.log(SKDevice);
		console.log(SKReader);
		const iv = new Uint8Array([
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // identifier
		  0x00, 0x00, 0x00, 0x01 // message counter
		]);

		let decryptedVerifierData;
		try {
			decryptedVerifierData = await decryptMessage(SKDevice, iv, verifierData, true);
		} catch (e) {
			console.log(e);
		}
		console.log(decryptedVerifierData);
		try {
			decryptedVerifierData = await decryptMessage(SKReader, iv, verifierData, true);
		} catch (e) {
			console.log(e);
		}
		console.log(decryptedVerifierData);
		if (decryptedVerifierData) {
			const mdocRequestDecoded = cborDecode(decryptedVerifierData);
			console.log(mdocRequestDecoded);
			console.log(mdocRequestDecoded.get("docRequests"));
			console.log(mdocRequestDecoded.get("docRequests")[0].get("itemsRequest"));
			console.log(mdocRequestDecoded.get("docRequests")[0].get("itemsRequest").data);
			console.log(mdocRequestDecoded.get("docRequests")[0].get("itemsRequest").buffer);
			console.log(mdocRequestDecoded.get("docRequests")[0].get("itemsRequest").data.get("nameSpaces"));
			console.log(mdocRequestDecoded.get("docRequests")[0].get("itemsRequest").data.get("nameSpaces").get("eu.europa.ec.eudi.pid.1"));
			const fields :Map<string, boolean>= mdocRequestDecoded.get("docRequests")[0].get("itemsRequest").data.get("nameSpaces").get("eu.europa.ec.eudi.pid.1");

			const fieldsPEX = [];
			fields.forEach((value, key, map) => {
				fieldsPEX.push(          {
					"name": key,
					"path": [
						`$['eu.europa.ec.eudi.pid.1']['${key}']`
					],
					"intent_to_retain": value
				},)
			})
			console.log(fieldsPEX);
			const fullPEX = {
				"id": "MdocPID",
				"title": "MDOC PID",
				"description": "Placeholder description",
				"input_descriptors": [
					{
						"id": "eu.europa.ec.eudi.pid.1",
						"format": {
							"mso_mdoc": {
								"alg": [
									"ES256"
								]
							},
						},
						"constraints": {
							"limit_disclosure": "required",
							"fields": fieldsPEX
						}
					}
				]
			}

			console.log(fullPEX);
			console.log(JSON.stringify(fullPEX));
		}
		// console.log(JSON.stringify(verifierPublicKey));
		return;
	}
}