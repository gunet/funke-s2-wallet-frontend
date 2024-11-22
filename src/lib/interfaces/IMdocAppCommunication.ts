export interface IMdocAppCommunication {
	ephemeralKey: CryptoKeyPair;
	generateEngagementQR() :Promise<string>
	communicationSubphase(uuid: string,  deviceEngagementBytes: Buffer) :Promise<void>
}