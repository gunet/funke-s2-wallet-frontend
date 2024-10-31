import React, { useState, useEffect, useContext } from 'react';
import { useTranslation } from 'react-i18next';

import StatusContext from '../../context/StatusContext';
import SessionContext from '../../context/SessionContext';
import RedirectPopup from '../../components/Popups/RedirectPopup';
import { H1 } from '../../components/Shared/Heading';
import Button from '../../components/Buttons/Button';
import PageDescription from '../../components/Shared/PageDescription';
import ContainerContext from '../../context/ContainerContext';

function highlightBestSequence(issuer, search) {
	if (typeof issuer !== 'string' || typeof search !== 'string') {
		return issuer;
	}

	const searchRegex = new RegExp(search, 'gi');
	const highlighted = issuer.replace(searchRegex, '<span class="font-bold text-primary dark:text-primary-light">$&</span>');

	return highlighted;
}

const Issuers = () => {
	const { isOnline } = useContext(StatusContext);
	const { api, keystore } = useContext(SessionContext);
	const [searchQuery, setSearchQuery] = useState('');
	const [issuers, setIssuers] = useState([]);
	const [filteredIssuers, setFilteredIssuers] = useState([]);
	const [showRedirectPopup, setShowRedirectPopup] = useState(false);
	const [selectedIssuer, setSelectedIssuer] = useState(null);
	const [loading, setLoading] = useState(false);
	const [availableCredentialConfigurations, setAvailableCredentialConfigurations] = useState(null);

	const container = useContext(ContainerContext);
	const { t } = useTranslation();

	useEffect(() => {
		const fetchIssuers = async () => {
			try {
				const response = await api.getExternalEntity('/issuer/all');
				let fetchedIssuers = response.data;
				fetchedIssuers = await Promise.all(fetchedIssuers.map(async (issuer) => {
					try {
						const metadata = (await container.openID4VCIHelper.getCredentialIssuerMetadata(issuer.credentialIssuerIdentifier)).metadata;
						return {
							...issuer,
							selectedDisplay: metadata?.display?.filter((display) => display.locale === 'en-US')[0] ? metadata.display.filter((display) => display.locale === 'en-US')[0] : null,
							credentialIssuerMetadata: metadata,
						}
					}
					catch (err) {
						console.error(err);
						return null;
					}

				}));
				fetchedIssuers = fetchedIssuers.filter((issuer) => issuer !== null);
				fetchedIssuers = fetchedIssuers.filter((issuer) => issuer.visible === 1); // show only visible issuers
				setIssuers(fetchedIssuers);
				setFilteredIssuers(fetchedIssuers);
			} catch (error) {
				console.error('Error fetching issuers:', error);
			}
		};

		if (container) {
			fetchIssuers();
		}
	}, [api, container]);

	const handleSearch = (event) => {
		const query = event.target.value;
		setSearchQuery(query);
	};

	useEffect(() => {
		const filtered = issuers.filter((issuer) => {
			const friendlyName = issuer?.selectedDisplay.name ?? "Uknown"
			const query = searchQuery.toLowerCase();
			return friendlyName.includes(query);
		});

		setFilteredIssuers(filtered);
	}, [searchQuery, issuers]);

	const handleIssuerClick = async (credentialIssuerIdentifier) => {
		const clickedIssuer = issuers.find((issuer) => issuer.credentialIssuerIdentifier === credentialIssuerIdentifier);
		if (clickedIssuer) {
			const cl = container.openID4VCIClients[credentialIssuerIdentifier];
			if (!cl) {
				return;
			}
			const confs = await cl.getAvailableCredentialConfigurations();
			setAvailableCredentialConfigurations(confs);
			setSelectedIssuer(clickedIssuer);
			setShowRedirectPopup(true);
		}
	};

	const handleCancel = () => {
		setShowRedirectPopup(false);
		setSelectedIssuer(null);
	};

	const handleContinue = (selectedConfigurationId) => {
		setLoading(true);

		if (selectedIssuer && selectedIssuer.credentialIssuerIdentifier) {
			const cl = container.openID4VCIClients[selectedIssuer.credentialIssuerIdentifier];
			const userHandleB64u = keystore.getUserHandleB64u();
			if (userHandleB64u == null) {
				console.error("Could not generate authorization request because user handle is null");
				return;
			}
			cl.generateAuthorizationRequest(selectedConfigurationId, userHandleB64u).then(({ url }) => {
				if (url) {
					window.location.href = url;
				}
			}).catch((err) => {
				console.error(err)
				console.error("Couldn't generate authz req")
			});
		}

		setLoading(false);
		setShowRedirectPopup(false);
	};

	return (
		<>
			<div className="sm:px-6 w-full">
				<H1 heading={t('common.navItemAddCredentials')} />
				<PageDescription description={t('pageAddCredentials.description')} />

				<div className="my-4">
					<input
						type="text"
						placeholder={t('pageAddCredentials.searchPlaceholder')}
						className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 dark:bg-gray-800 dark:text-white rounded-lg focus:outline-none focus:ring-blue-500 focus:border-blue-500 dark:inputDarkModeOverride"
						value={searchQuery}
						onChange={handleSearch}
					/>
				</div>
				{filteredIssuers.length === 0 ? (
					<p className="text-gray-700 dark:text-gray-300 mt-4">{t('pageAddCredentials.noFound')}</p>
				) : (
					<div
						className="max-h-screen-80 overflow-y-auto space-y-2"
						style={{ maxHeight: '80vh' }}
					>
						{filteredIssuers.map((issuer) => (
							<Button
								variant="outline"
								additionalClassName="break-words w-full text-left"
								key={issuer.id}
								style={{ wordBreak: 'break-all' }}
								onClick={() => handleIssuerClick(issuer.credentialIssuerIdentifier)}
								disabled={!isOnline}
								title={!isOnline ? t('common.offlineTitle') : ''}
							>
								<div dangerouslySetInnerHTML={{ __html: highlightBestSequence(issuer.credentialIssuerMetadata.display[0]?.name ?? "Uknown", searchQuery) }} />
							</Button>
						))}
					</div>
				)}
			</div>

			{showRedirectPopup && (
				<RedirectPopup
					loading={loading}
					onClose={handleCancel}
					handleContinue={handleContinue}
					availableCredentialConfigurations={availableCredentialConfigurations}
					popupTitle={`${t('pageAddCredentials.popup.title')} ${selectedIssuer?.selectedDisplay?.name ?? "Uknown"}`}
					popupMessage={t('pageAddCredentials.popup.message', { issuerName: selectedIssuer?.selectedDisplay?.name ?? "Uknown" })}
				/>
			)}
		</>
	);
};

export default Issuers;
