import { useEffect, useState, useContext, useMemo } from "react";
import { DIContainer } from "../lib/DIContainer";
import { IHttpProxy } from "../lib/interfaces/IHttpProxy";
import { IOpenID4VCIClient } from "../lib/interfaces/IOpenID4VCIClient";
import { IOpenID4VCIClientStateRepository } from "../lib/interfaces/IOpenID4VCIClientStateRepository";
import { IOpenID4VCIHelper } from "../lib/interfaces/IOpenID4VCIHelper";
import { HttpProxy } from "../lib/services/HttpProxy";
import { OpenID4VCIClientFactory } from "../lib/services/OpenID4VCIClientFactory";
import { OpenID4VCIClientStateRepository } from "../lib/services/OpenID4VCIClientStateRepository";
import { OpenID4VCIHelper } from "../lib/services/OpenID4VCIHelper";
import { ClientConfig } from "../lib/types/ClientConfig";
import { StorableCredential } from "../lib/types/StorableCredential";
import { IOpenID4VPRelyingParty } from "../lib/interfaces/IOpenID4VPRelyingParty";
import { OpenID4VPRelyingParty } from "../lib/services/OpenID4VPRelyingParty";
import { IOpenID4VPRelyingPartyStateRepository } from "../lib/interfaces/IOpenID4VPRelyingPartyStateRepository";
import { OpenID4VPRelyingPartyStateRepository } from "../lib/services/OpenID4VPRelyingPartyStateRepository";
import SessionContext from "../context/SessionContext";
import { ICredentialParserRegistry } from "../lib/interfaces/ICredentialParser";
import { CredentialParserRegistry } from "../lib/services/CredentialParserRegistry";
import { parseSdJwtCredential } from "../functions/parseSdJwtCredential";
import { CredentialConfigurationSupported } from "../lib/schemas/CredentialConfigurationSupportedSchema";
import { generateRandomIdentifier } from "../lib/utils/generateRandomIdentifier";
import { fromBase64 } from "../util";
import defaulCredentialImage from "../assets/images/cred.png";
import { UserData } from "../api/types";

export type ContainerContextValue = {
	httpProxy: IHttpProxy,
	openID4VPRelyingParty: IOpenID4VPRelyingParty,
	openID4VCIHelper: IOpenID4VCIHelper,
	openID4VCIClients: { [x: string]: IOpenID4VCIClient },
	credentialParserRegistry: ICredentialParserRegistry,
}


const defaultLocale = 'en-US';

export function useContainer() {
	const { isLoggedIn, api, keystore } = useContext(SessionContext);

	const [trustedCredentialIssuers, setTrustedCredentialIssuers] = useState(null)

	const cont = new DIContainer();

	const [container, setContainer] = useState<ContainerContextValue>(null);
	const [userData, setUserData] = useState<UserData>(null);

	useEffect(() => {
		if (isLoggedIn && api) {
			api.getExternalEntity('/issuer/all').then((response) => {
				setTrustedCredentialIssuers(response.data)
			}).catch(err => {
				setTrustedCredentialIssuers([]);
			});

			api.get('/user/session/account-info').then((response) => {
				setUserData(response.data);
			}).catch(() => console.log("Failed to load account info"));

		}
	}, [isLoggedIn, api]);


	async function initialize() {

		cont.register<IHttpProxy>('HttpProxy', HttpProxy);
		cont.register<IOpenID4VPRelyingPartyStateRepository>('OpenID4VPRelyingPartyStateRepository', OpenID4VPRelyingPartyStateRepository);

		cont.register<ICredentialParserRegistry>('CredentialParserRegistry', CredentialParserRegistry);

		cont.register<IOpenID4VCIClientStateRepository>('OpenID4VCIClientStateRepository', OpenID4VCIClientStateRepository, userData.settings.openidRefreshTokenMaxAgeInSeconds);
		cont.register<IOpenID4VCIHelper>('OpenID4VCIHelper', OpenID4VCIHelper, cont.resolve<IHttpProxy>('HttpProxy'));
		const credentialParserRegistry = cont.resolve<ICredentialParserRegistry>('CredentialParserRegistry');

		credentialParserRegistry.addParser({
			async parse(rawCredential) {

				if (typeof rawCredential != 'string') {
					return { error: "rawCredential not of type 'string'" };

				}
				const result = await parseSdJwtCredential(rawCredential);
				if ('error' in result) {
					return { error: "Failed to parse sdjwt" };
				}

				const { metadata } = await cont.resolve<IOpenID4VCIHelper>('OpenID4VCIHelper').getCredentialIssuerMetadata(result.beautifiedForm.iss);
				const credentialConfigurationSupportedObj: CredentialConfigurationSupported | undefined = Object.values(metadata.credential_configurations_supported)
					.filter((x: any) => x?.vct && result.beautifiedForm?.vct && x.vct === result.beautifiedForm?.vct)
				[0];

				const credentialHeader = JSON.parse(new TextDecoder().decode(fromBase64(rawCredential.split('.')[0] as string)));

				const credentialImageSvgTemplateURL = credentialHeader?.vctm?.display &&
					credentialHeader.vctm.display[0] && credentialHeader.vctm.display[0][defaultLocale] &&
					credentialHeader.vctm.display[0][defaultLocale]?.rendering?.svg_templates.length > 0 ?
					credentialHeader.vctm.display[0][defaultLocale]?.rendering?.svg_templates[0]?.uri
					: null;

				let credentialFriendlyName = credentialHeader?.vctm?.display && credentialHeader.vctm.display[0] && credentialHeader.vctm.display[0][defaultLocale] ?
					credentialHeader.vctm.display[0][defaultLocale]?.name
					: null;

				// get credential friendly name from openid credential issuer metadata
				if (!credentialFriendlyName && credentialConfigurationSupportedObj && credentialConfigurationSupportedObj?.display && credentialConfigurationSupportedObj?.display.length > 0) {
					credentialFriendlyName = credentialConfigurationSupportedObj?.display[0]?.name;
				}

				if (!credentialFriendlyName) { // fallback value
					credentialFriendlyName = "Credential";
				}

				if (credentialImageSvgTemplateURL) {
					return {
						beautifiedForm: result.beautifiedForm,
						credentialImage: {
							credentialImageSvgTemplateURL: credentialImageSvgTemplateURL
						},
						credentialFriendlyName,
					}
				}
				else if (credentialHeader?.vctm || credentialConfigurationSupportedObj) {
					let credentialImageURL = credentialHeader?.vctm?.display && credentialHeader.vctm.display[0] && credentialHeader.vctm.display[0][defaultLocale] ?
						credentialHeader.vctm.display[0][defaultLocale]?.rendering?.simple?.logo?.uri
						: null;

					if (!credentialImageURL) { // provide fallback method through the OpenID credential issuer metadata
						credentialImageURL = credentialConfigurationSupportedObj?.display?.length > 0 ? credentialConfigurationSupportedObj.display[0]?.background_image?.uri : null;
					}
					if (!credentialImageURL) {
						credentialImageURL = credentialConfigurationSupportedObj?.display?.length > 0 ? credentialConfigurationSupportedObj.display[0]?.logo?.url : null;
					}
					if (!credentialImageURL) {
						credentialImageURL = defaulCredentialImage;
					}

					return {
						beautifiedForm: result.beautifiedForm,
						credentialImage: {
							credentialImageURL: credentialImageURL,
						},
						credentialFriendlyName,
					}
				}

				return {
					beautifiedForm: result.beautifiedForm,
					credentialImage: {
						credentialImageURL: defaulCredentialImage,
					},
					credentialFriendlyName,
				}

			},
		});

		cont.register<IOpenID4VPRelyingParty>('OpenID4VPRelyingParty', OpenID4VPRelyingParty,
			cont.resolve<IOpenID4VPRelyingPartyStateRepository>('OpenID4VPRelyingPartyStateRepository'),
			cont.resolve<IHttpProxy>('HttpProxy'),
			cont.resolve<ICredentialParserRegistry>('CredentialParserRegistry'),
			async function getAllStoredVerifiableCredentials() {
				const fetchAllCredentials = await api.get('/storage/vc');
				return { verifiableCredentials: fetchAllCredentials.data.vc_list };
			},

			async function signJwtPresentationKeystoreFn(nonce: string, audience: string, verifiableCredentials: any[]): Promise<{ vpjwt: string }> {
				return keystore.signJwtPresentation(nonce, audience, verifiableCredentials)
			},

			async function storeVerifiablePresentation(presentation: string, format: string, identifiersOfIncludedCredentials: string[], presentationSubmission: any, audience: string) {
				await api.post('/storage/vp', {
					presentationIdentifier: generateRandomIdentifier(32),
					presentation,
					presentationSubmission,
					includedVerifiableCredentialIdentifiers: identifiersOfIncludedCredentials,
					audience,
					issuanceDate: new Date().toISOString(),
				});
			}
		);

		cont.register<OpenID4VCIClientFactory>('OpenID4VCIClientFactory', OpenID4VCIClientFactory,
			cont.resolve<IHttpProxy>('HttpProxy'),
			cont.resolve<IOpenID4VCIClientStateRepository>('OpenID4VCIClientStateRepository'),
			async (cNonce: string, audience: string, clientId: string): Promise<{ jws: string }> => {
				const [{ proof_jwt }, newPrivateData, keystoreCommit] = await keystore.generateOpenid4vciProof(cNonce, audience, clientId);
				await api.updatePrivateData(newPrivateData);
				await keystoreCommit();
				return { jws: proof_jwt };
			},
			async function storeCredential(c: StorableCredential) {
				await api.post('/storage/vc', {
					...c
				});
			},
			async function authorizationRequestModifier(credentialIssuerIdentifier: string, url: string, request_uri?: string, client_id?: string) {
				if (credentialIssuerIdentifier !== process.env.REACT_APP_PID_CREDENTIAL_ISSUER_IDENTIFIER) {
					return { url };
				}
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
		);


		const httpProxy = cont.resolve<IHttpProxy>('HttpProxy');
		const openID4VCIHelper = cont.resolve<IOpenID4VCIHelper>('OpenID4VCIHelper');

		const openID4VPRelyingParty = cont.resolve<IOpenID4VPRelyingParty>('OpenID4VPRelyingParty');

		let openID4VCIClientsJson: { [x: string]: IOpenID4VCIClient } = {};

		let clientConfigs: ClientConfig[] = await Promise.all(trustedCredentialIssuers.map(async (credentialIssuer) => {
			const [authorizationServerMetadata, credentialIssuerMetadata] = await Promise.all([
				openID4VCIHelper.getAuthorizationServerMetadata(credentialIssuer.credentialIssuerIdentifier).catch((err) => null),
				openID4VCIHelper.getCredentialIssuerMetadata(credentialIssuer.credentialIssuerIdentifier).catch((err) => null),
			]);
			if (!authorizationServerMetadata || !credentialIssuerMetadata) {
				console.error("Either authorizationServerMetadata or credentialIssuerMetadata could not be loaded");
				return null;
			}
			return {
				clientId: credentialIssuer.clientId,
				credentialIssuerIdentifier: credentialIssuer.credentialIssuerIdentifier,
				credentialIssuerMetadata: credentialIssuerMetadata.metadata,
				authorizationServerMetadata: authorizationServerMetadata.authzServeMetadata,
			}
		}));

		clientConfigs = clientConfigs.filter((conf) => conf != null);


		const openID4VCIClientFactory = cont.resolve<OpenID4VCIClientFactory>('OpenID4VCIClientFactory');

		for (const config of clientConfigs) {
			const openID4VCIClient = openID4VCIClientFactory.createClient(config);
			openID4VCIClientsJson[config.credentialIssuerIdentifier] = openID4VCIClient;
		}
		return { openID4VCIClientsJson, openID4VPRelyingParty, httpProxy, openID4VCIHelper, credentialParserRegistry };
	}

	useEffect(() => {
		if (isLoggedIn && trustedCredentialIssuers && keystore && userData) {
			console.log("container instance created...");
			initialize().then(({ openID4VCIClientsJson, openID4VPRelyingParty, httpProxy, openID4VCIHelper, credentialParserRegistry }) => {
				setContainer({
					openID4VCIClients: openID4VCIClientsJson,
					openID4VPRelyingParty,
					httpProxy,
					openID4VCIHelper,
					credentialParserRegistry,
				});
			});
		}
	}, [isLoggedIn, trustedCredentialIssuers, keystore, userData])

	return useMemo(() => {
		return { container }
	}, [isLoggedIn, trustedCredentialIssuers, container, keystore, userData])
}
