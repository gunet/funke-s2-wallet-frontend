// External libraries
import React, { useState, useEffect, useContext } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useTranslation, Trans } from 'react-i18next';
import QRCode from "react-qr-code";
import { BsQrCode, BsCheckCircle } from "react-icons/bs";

// Contexts
import SessionContext from '../../context/SessionContext';
import ContainerContext from '../../context/ContainerContext';

// Hooks
import useFetchPresentations from '../../hooks/useFetchPresentations';
import useScreenType from '../../hooks/useScreenType';

// Components
import CredentialTabs from '../../components/Credentials/CredentialTabs';
import CredentialInfo from '../../components/Credentials/CredentialInfo';
import CredentialJson from '../../components/Credentials/CredentialJson';
import HistoryList from '../../components/History/HistoryList';
import CredentialDeleteButton from '../../components/Credentials/CredentialDeleteButton';
import DeletePopup from '../../components/Popups/DeletePopup';
import Button from '../../components/Buttons/Button';
import CredentialLayout from '../../components/Credentials/CredentialLayout';
import PopupLayout from '../../components/Popups/PopupLayout';
import Spinner from '../../components/Shared/Spinner';

const Credential = () => {
	const { credentialId } = useParams();
	const { api } = useContext(SessionContext);
	const container = useContext(ContainerContext);
	const history = useFetchPresentations(api, credentialId, null);

	const [vcEntity, setVcEntity] = useState(null);
	const [showDeletePopup, setShowDeletePopup] = useState(false);
	const [loading, setLoading] = useState(false);
	const [credentialFiendlyName, setCredentialFriendlyName] = useState(null);
	const screenType = useScreenType();
	const [activeTab, setActiveTab] = useState(0);
	const [showMdocQR, setShowMdocQR] = useState(false);
	const [mdocQRStatus, setMdocQRStatus] = useState(0); // 0 init; 1 loading; 2 finished;
	const [shareWithQr, setShareWithQr] = useState(false);
	const [mdocQRContent, setMdocQRContent] = useState("");
	const navigate = useNavigate();
	const { t } = useTranslation();

	useEffect(() => {
		const getData = async () => {
			const response = await api.get('/storage/vc');
			const vcEntity = response.data.vc_list
				.filter((vcEntity) => vcEntity.credentialIdentifier === credentialId)[0];
			if (!vcEntity) {
				throw new Error("Credential not found");
			}
			setVcEntity(vcEntity);
		};

		getData();
	}, [api, credentialId]);

	useEffect(() => {
		if (!vcEntity || !container) {
			return;
		}
		container.credentialParserRegistry.parse(vcEntity.credential).then((c) => {
			if ('error' in c) {
				return;
			}
			setCredentialFriendlyName(c.credentialFriendlyName);
		});
	}, [vcEntity, container]);

	const handleSureDelete = async () => {
		setLoading(true);
		try {
			await api.del(`/storage/vc/${vcEntity.credentialIdentifier}`);
		} catch (error) {
			console.error('Failed to delete data', error);
		}
		setLoading(false);
		setShowDeletePopup(false);
		window.location.href = '/';
	};

	const infoTabs = [
		{ label: t('pageCredentials.datasetTitle'), component: <CredentialJson credential={vcEntity?.credential} /> },
		{
			label: t('pageCredentials.presentationsTitle'), component:
				<>
					{history.length === 0 ? (
						<p className="text-gray-700 dark:text-white">
							{t('pageHistory.noFound')}
						</p>
					) : (
						<HistoryList history={history} />
					)}
				</>
		}
	];

	const generateQR = async () => {
		setMdocQRStatus(0);
		setMdocQRContent(await container.mdocAppCommunication.generateEngagementQR(vcEntity.credential));
		setShowMdocQR(true);
		const client = await container.mdocAppCommunication.startClient();
		if (!client) {
			setMdocQRStatus(-1);
		} else {
			setMdocQRStatus(1);
			await container.mdocAppCommunication.communicationSubphase();
			setMdocQRStatus(2);
		}
	};

	useEffect(() => {
		console.log("Triggered transaction thing: ", container.mdocAppCommunication.transactionPending)
	}, [container.mdocAppCommunication])

	useEffect(() => {
		async function canWeShareQR(credential) {
			if (!window.nativeWrapper) {
				setShareWithQr(false);
				return;
			}
			const mdoc = await container.credentialParserRegistry.parse(credential);
			if (mdoc?.parsedBy === 'mdocPIDParser') {
				setShareWithQr(true);
			} else {
				setShareWithQr(false);
			}
		}

		if (vcEntity?.credential && container) {
			canWeShareQR(vcEntity?.credential);
		}
	}, [vcEntity, container]);


	return (
		<CredentialLayout title={t('pageCredentials.credentialTitle')}>
			<>
				<div className="flex flex-col lg:flex-row w-full md:w-1/2 lg:mt-5 mt-0">

					{/* Block 2: Information List */}
					{vcEntity && <CredentialInfo credential={vcEntity.credential} />} {/* Use the CredentialInfo component */}
				</div>

				<div className="w-full pt-2 px-2">
					{screenType !== 'mobile' ? (
						<>
							<CredentialTabs tabs={infoTabs} activeTab={activeTab} onTabChange={setActiveTab} />
							<div className='py-2'>
								{infoTabs[activeTab].component}
							</div>
						</>
					) : (
						<>
							<Button
								variant="primary"
								onClick={() => navigate(`/credential/${credentialId}/history`)}
								additionalClassName='w-full my-2'
							>
								{t('pageCredentials.presentationsTitle')}
							</Button>

							<Button
								variant="primary"
								onClick={() => navigate(`/credential/${credentialId}/details`)}
								additionalClassName='w-full my-2'
							>
								{t('pageCredentials.datasetTitle')}
							</Button>
						</>
					)}
				</div>
				<div className='px-2 w-full'>
				{shareWithQr && (<Button variant='primary' additionalClassName='w-full my-2' onClick={generateQR}>{<span className='px-1'><BsQrCode/></span>}Share using QR Code</Button>)}
					<PopupLayout isOpen={showMdocQR}>
					<div className="flex items-start justify-between mb-2">
						<h2 className="text-lg font-bold text-primary">
							Share using QRCode
						</h2>
						</div>
						<hr className="mb-2 border-t border-primary/80" />
						<span>
								{mdocQRStatus === -1 && 
									<span>
										We couldn't access nearby device features. Please enable nearby devices permissions in your settings and restart the app to "Share with QRCode".
									</span>}
								{mdocQRStatus === 0 && <span className='flex items-center justify-center'><QRCode value={mdocQRContent} /></span>}
								{mdocQRStatus === 1 && <span>Communicating with verifier...</span>}
								{mdocQRStatus === 2 && <span className='flex items-center justify-center mt-10'><BsCheckCircle color='green' size={100}/></span>}
						</span>
						<div className="flex justify-end space-x-2 pt-4">
								{mdocQRStatus !== 1 && <Button variant='primary' onClick={() => setShowMdocQR(false)}>Close</Button>}
					</div>
					</PopupLayout>
				</div>
				<div className='px-2 w-full'>
					<CredentialDeleteButton onDelete={() => { setShowDeletePopup(true); }} />
				</div>
				{/* Delete Credential Popup */}
				{showDeletePopup && vcEntity && (
					<DeletePopup
						isOpen={showDeletePopup}
						onConfirm={handleSureDelete}
						onClose={() => setShowDeletePopup(false)}
						message={
							<Trans
								i18nKey="pageCredentials.deletePopupMessage"
								values={{ credentialName: credentialFiendlyName }}
								components={{ strong: <strong />, br: <br /> }}
							/>
						}
						loading={loading}
					/>
				)}
			</>
		</CredentialLayout>
	);
};

export default Credential;
