import { DeviceSignedDocument, parse } from "@auth0/mdl";
import { ICredentialParser } from "../interfaces/ICredentialParser";
import { PresentationDefinitionType } from "../types/presentationDefinition.type";
import * as cbor from 'cbor-x';
import * as jose from 'jose';
import defaulCredentialImage from "../../assets/images/cred.png";


export const deviceResponseParser: ICredentialParser = {
	parse: async function (rawCredential: object | string, presentationDefinitionFilter?: PresentationDefinitionType): Promise<{ credentialFriendlyName: string; credentialImage: { credentialImageURL: string; } | { credentialImageSvgTemplateURL: string; }; beautifiedForm: any; } | { error: string; }> {

		if (typeof rawCredential != 'string') {
			return { error: "Not for this parser" };
		}

		try {
			const decodedCred = jose.base64url.decode(rawCredential)
			const parsedMDOC = parse(decodedCred);
			const [parsedDocument] = parsedMDOC.documents as DeviceSignedDocument[];
			const namespace = parsedDocument.issuerSignedNameSpaces[0];

			const attrValues = parsedDocument.getIssuerNameSpace(namespace);
			return {
				credentialFriendlyName: parsedDocument.issuerSignedNameSpaces[0],
				credentialImage: {
					credentialImageURL: defaulCredentialImage,
				},
				beautifiedForm: attrValues,
			}
		}
		catch (err) {
			return { error: "Failed to parse mdoc device response" };
		}
	}
}

export const mdocPIDParser: ICredentialParser = {
	parse: async function (rawCredential: object | string, presentationDefinitionFilter?: PresentationDefinitionType): Promise<{ credentialFriendlyName: string; credentialImage: { credentialImageURL: string; } | { credentialImageSvgTemplateURL: string; }; beautifiedForm: any; } | { error: string; }> {
		console.log("Raw cred = ", rawCredential)
		if (typeof rawCredential != 'string') {
			return { error: "Not for this parser" };
		}

		try {
			const credentialBytes = jose.base64url.decode(rawCredential);
			const issuerSigned = cbor.decode(credentialBytes);
			const m = {
				version: '1.0',
				documents: [new Map([
					['docType', 'eu.europa.ec.eudi.pid.1'],
					['issuerSigned', issuerSigned]
				])],
				status: 0
			};
			const encoded = cbor.encode(m);
			const mdoc = parse(encoded);
			const [parsedDocument] = mdoc.documents;
			const namespace = parsedDocument.issuerSignedNameSpaces[0]
			const attrValues = parsedDocument.getIssuerNameSpace(namespace);

			return {
				credentialFriendlyName: namespace,
				credentialImage: {
					credentialImageURL: defaulCredentialImage,
				},
				beautifiedForm: attrValues,
			}
		}
		catch (err) {
			return { error: "Failed to parse mdoc PID" };
		}
	}
}
