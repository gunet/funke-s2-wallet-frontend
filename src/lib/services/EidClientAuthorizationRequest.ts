

export class EidClientAuthorizationRequest {

	constructor() { }

	getCredentialIssuerIdentifier(): string {
		return "https://demo.pid-issuer.bundesdruckerei.de/c";
	}

	async handle(url: string, client_id: string, request_uri: string): Promise<{ url: string }> {
		const isMobile = window.innerWidth <= 480;
		const eIDClientURL = isMobile ? process.env.REACT_APP_OPENID4VCI_EID_CLIENT_URL.replace('http', 'eid') : process.env.REACT_APP_OPENID4VCI_EID_CLIENT_URL;
		console.log("Eid client url = ", eIDClientURL)
		const urlObj = new URL(url);
		// Construct the base URL
		const baseUrl = `${urlObj.protocol}//${urlObj.hostname}${urlObj.pathname}`;

		// Parameters
		// Encode parameters
		const encodedClientId = encodeURIComponent(client_id);
		const encodedRequestUri = encodeURIComponent(request_uri);
		const tcTokenURL = `${baseUrl}?client_id=${encodedClientId}&request_uri=${encodedRequestUri}`;

		const newLoc = `${eIDClientURL}?tcTokenURL=${encodeURIComponent(tcTokenURL)}`

		console.log("new loc = ", newLoc)
		return {
			url: newLoc
		};
	}
}