import { IMdocAppCommunication } from "../interfaces/IMdocAppCommunication";
import { DataItem, MDoc, parse } from "@auth0/mdl";
import { cborDecode, cborEncode } from "../utils/cbor";
import { v4 as uuidv4 } from 'uuid';
import { encryptMessage, decryptMessage, hexToUint8Array, uint8ArrayToBase64Url, deriveSharedSecret, getKey, uint8ArraytoHexString, getSessionTranscriptBytes, getDeviceEngagement } from "../utils/mdocProtocol";
import { base64url } from "jose";


export class MdocAppCommunication implements IMdocAppCommunication {
	constructor(
		private generateDeviceResponseFn: (mdocCredential: MDoc, presentationDefinition: any, sessionTranscripBytes: any) => Promise<{ deviceResponseMDoc: MDoc }>,
	) { }

	ephemeralKey: CryptoKeyPair;
	
	async generateEngagementQR(credential :any) {
		const keyPair = await crypto.subtle.generateKey(
			{
				name: "ECDH",
				namedCurve: "P-256", // the named curve for P-256
			},
			true, // whether the key is extractable (e.g., can be exported)
			["deriveKey", "deriveBits"] // can be used for signing and verification
		);
		this.ephemeralKey = keyPair;

		const publicKeyJWK = await crypto.subtle.exportKey("jwk", keyPair.publicKey);


		// const uuid = uuidv4()
		const uuid =  '00179c7a-eec6-4f88-8646-045fda9ac4d8'
		
		const deviceEngagement = getDeviceEngagement(uuid, publicKeyJWK);

		const cbor = cborEncode(deviceEngagement);

		this.communicationSubphase(uuid, DataItem.fromData(deviceEngagement), credential);
		return `mdoc:${uint8ArrayToBase64Url(cbor)}`;
	}

	async communicationSubphase(uuid: string, deviceEngagementBytes: any, credential: any): Promise<void> {
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
		const sessionMessage = uint8ArraytoHexString(new Uint8Array(aggregatedData));
		const decoded = cborDecode(hexToUint8Array(sessionMessage));
		const readerKey = decoded.get('eReaderKey');
		const verifierData = decoded.get('data');
		const coseKey = cborDecode(new Uint8Array(readerKey.buffer));
		const verifierJWK = {
			kty: "EC",
			alg: "ECDH",
			crv: "P-256",
			x: uint8ArrayToBase64Url(coseKey.get(-2)),
			y: uint8ArrayToBase64Url(coseKey.get(-3))
		}
		const verifierPublicKey = await crypto.subtle.importKey("jwk", verifierJWK, {name: "ECDH", namedCurve: "P-256"}, true, []);
		const sessionTranscriptBytes = getSessionTranscriptBytes(
			deviceEngagementBytes, // DeviceEngagementBytes
			decoded.get('eReaderKey'), // EReaderKeyBytes
		);
		const zab = await deriveSharedSecret(this.ephemeralKey.privateKey, verifierPublicKey);
		const salt = await crypto.subtle.digest("SHA-256", sessionTranscriptBytes);
		const SKDevice = await getKey(zab, salt, "SKDevice");
		const SKReader = await getKey(zab, salt, "SKReader");
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

			const presentationDefinition = fullPEX;
			const credentialBytes = base64url.decode(credential);
			const issuerSigned = cborDecode(credentialBytes);
			// const descriptor = presentationDefinition.input_descriptors.filter((desc) => desc.id === descriptor_id)[0];
			const descriptor = {"id": "eu.europa.ec.eudi.pid.1"}
			const m = {
				version: '1.0',
				documents: [new Map([
					['docType', descriptor.id],
					['issuerSigned', issuerSigned]
				])],
				status: 0
			};
			const encoded = cborEncode(m);
			const mdoc = parse(encoded);

			const { deviceResponseMDoc } = await this.generateDeviceResponseFn(mdoc, fullPEX, sessionTranscriptBytes);

			// encrypt mdoc response
			const iv = new Uint8Array([
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // identifier
				0x00, 0x00, 0x00, 0x01 // message counter
			]);

			console.log("Device response: ");
			console.log(uint8ArraytoHexString(deviceResponseMDoc.encode()));
			const encryptedMdoc = (await encryptMessage(SKDevice, deviceResponseMDoc.encode(), iv)).ciphertext;

			const sessionData = {
				data: encryptedMdoc,
				status: 20
			}

			const sessionDataEncoded = cborEncode(sessionData);

			let toSendBytes = Array.from(sessionDataEncoded);
			while (toSendBytes.length > 19){
				const chunk = [1, ...toSendBytes.slice(0, 19)]
				console.log(chunk);
				/* @ts-ignore */
				const send = await nativeWrapper.bluetoothSendToServer(JSON.stringify(chunk));
				console.log(send);
				toSendBytes = toSendBytes.slice(19);
			}
			/* @ts-ignore */
			const send = await nativeWrapper.bluetoothSendToServer(JSON.stringify([0, ...toSendBytes]));
			console.log(send);

		}
		return;
	}
}