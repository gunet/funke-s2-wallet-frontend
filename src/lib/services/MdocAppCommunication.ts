import { IMdocAppCommunication } from "../interfaces/IMdocAppCommunication";
import { cborEncode } from "../utils/cbor";
import { DataItem, MDoc } from "@auth0/mdl";
import { v4 as uuidv4 } from 'uuid';

export class MdocAppCommunication implements IMdocAppCommunication {
	constructor(
		private generateDeviceResponseFn: (mdocCredential: MDoc, presentationDefinition: any, sessionTranscripBytes: any) => Promise<{ deviceResponseMDoc: MDoc }>,
	) { }
	async generateEngagementQR() {
		console.log("Hello Engagement QR");

		const keyPair = await window.crypto.subtle.generateKey(
			{
				name: "ECDH",
				namedCurve: "P-256", // the named curve for P-256
			},
			true, // whether the key is extractable (e.g., can be exported)
			["deriveKey"] // can be used for signing and verification
		);

		console.log(keyPair.publicKey);
		const publicKeyJWK = await window.crypto.subtle.exportKey("jwk", keyPair.publicKey);
		console.log(publicKeyJWK);

		function uuidToUint8Array(uuid) {
			// Remove hyphens from the UUID string
			const hexString = uuid.replace(/-/g, '');

			// Create a Uint8Array with a length of 16 bytes (128 bits)
			const byteArray = new Uint8Array(16);

			// Fill the byte array with values by parsing the hex pairs
			for (let i = 0; i < 16; i++) {
				byteArray[i] = parseInt(hexString.slice(i * 2, i * 2 + 2), 16);
			}

			return byteArray;
		}

		const bleOptions = new Map<number, any>([
			[0, false],
			[1, true],
			[11, uuidToUint8Array(uuidv4())],
		]);

		function base64urlToUint8Array(base64url: string): Uint8Array {
			const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/'); // Base64url to Base64
			const binaryString = atob(base64);  // Decode base64 to binary string
			const byteArray = new Uint8Array(binaryString.length); // Create a Uint8Array of the same length

			// Populate the Uint8Array with byte values
			for (let i = 0; i < binaryString.length; i++) {
				byteArray[i] = binaryString.charCodeAt(i);
			}

			return byteArray;
		}

		function uint8ArrayToBase64Url(array: any) {
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

		function toHexString(byteArray: Uint8Array): string {
			return Array.from(byteArray, (byte: number) =>
				('0' + (byte & 0xFF).toString(16)).slice(-2)
			).join('');
		}

		const themap = new Map<number, any>();
		themap.set(0, "1.0");
		//@ts-ignore
		themap.set(1, [1, DataItem.fromData(new Map([[1, 2], [-1, 1],

		[-2, base64urlToUint8Array(publicKeyJWK.x)],
		[-3, base64urlToUint8Array(publicKeyJWK.y)]]))])
		themap.set(2, [[2, 1, bleOptions]]);

		const cbor = cborEncode(themap);

		console.log(cbor);

		console.log(toHexString(cbor));

		console.log(uint8ArrayToBase64Url(cbor));

		return `mdoc:${uint8ArrayToBase64Url(cbor)}`;
	}
}