import { MDoc } from "@auth0/mdl";

export interface IMdocAppCommunication {
	ephemeralKey: CryptoKeyPair;
	generateEngagementQR(credential: any) :Promise<string>
	communicationSubphase(uuid: string,  deviceEngagementBytes: Buffer, credential: any) :Promise<void>
}