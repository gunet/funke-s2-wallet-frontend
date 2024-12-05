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
import CredentialImage from '../../components/Credentials/CredentialImage';


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
	const [shareWithQrFilter, setShareWithQrFilter] = useState([]);
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
		}
	};

	const getMdocRequest = async () => {
		const fields = await container.mdocAppCommunication.getMdocRequest();
		setShareWithQrFilter(fields);
		setMdocQRStatus(2);
	}

	const sendMdocResponse = async () => {
		await container.mdocAppCommunication.sendMdocResponse();
		setMdocQRStatus(4);
	}

	const consentToShare = () => {
		setMdocQRStatus(3);
	}

	useEffect(() => {
		if (mdocQRStatus === 1) {
			// Got client
			getMdocRequest();
		} else if (mdocQRStatus === 3) {
			// Got consent
			sendMdocResponse();
		}
	}, [mdocQRStatus]);

	useEffect(() => {
		async function shareEligible(vcEntity) {
			if (!window.nativeWrapper) {
				setShareWithQr(false);
				return;
			}
			if (vcEntity.format == "mso_mdoc") {
				setShareWithQr(true);
			} else {
				setShareWithQr(false);
			}
		}

		if (vcEntity) {
			shareEligible(vcEntity);
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
					<PopupLayout fullScreen={true} isOpen={showMdocQR}>
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
								{mdocQRStatus === 0 && <div className='flex items-center justify-center'><QRCode value={mdocQRContent} /></div>}
								{(mdocQRStatus === 1 || mdocQRStatus === 3) && <span>Communicating with verifier...</span>}
								{mdocQRStatus === 2 && <span className='pb-16'>
									<p className="text-gray-700 dark:text-white text-sm mt-2 mb-4">
										A nearby verifier requested the following fields:
									</p>
									{vcEntity && <CredentialImage
										key={vcEntity.credentialIdentifier}
										credential={vcEntity.credential}
										className="w-full object-cover rounded-xl"
									/>}
									<div className={`flex flex-wrap justify-center flex flex-row justify-center items-center mb-2 pb-[20px] ${screenType === 'desktop' && 'overflow-y-auto items-center custom-scrollbar max-h-[20vh]'} ${screenType === 'tablet' && 'px-24'}`}>
										{vcEntity && <CredentialInfo mainClassName={"text-xs w-full"} display='all' credential={vcEntity?.credential} filter={shareWithQrFilter}/>}
									</div>
									<div className={`flex justify-between pt-4 z-10 ${screenType !== 'desktop' && 'fixed bottom-0 left-0 right-0 bg-white dark:bg-gray-800 flex px-6 pb-6 flex shadow-2xl rounded-t-lg w-auto'}`}>
										<Button variant='cancel' onClick={consentToShare}>Cancel</Button>
										<Button variant='primary' onClick={consentToShare}>Send</Button>
									</div>
									</span>}
								{mdocQRStatus === 4 && <span className='flex items-center justify-center mt-10'><BsCheckCircle color='green' size={100}/></span>}
								{![1,2].includes(mdocQRStatus) && 
									<div className={`flex justify-end pt-4 z-10 ${screenType !== 'desktop' && 'fixed bottom-0 left-0 right-0 bg-white dark:bg-gray-800 flex px-6 pb-6 flex shadow-2xl rounded-t-lg w-auto'}`}>
										<Button variant='primary' onClick={() => setShowMdocQR(false)}>Close</Button>
								</div>}
						</span>
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
