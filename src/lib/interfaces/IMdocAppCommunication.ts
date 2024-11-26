import { MDoc } from "@auth0/mdl";

export interface IMdocAppCommunication {
	ephemeralKey: CryptoKeyPair;
	uuid: string;
	deviceEngagementBytes: any;
	credential: any;
	generateEngagementQR(credential: any) :Promise<string>
	startClient() :Promise<boolean>
	communicationSubphase(uuid: string,  deviceEngagementBytes: Buffer, credential: any) :Promise<void>
}