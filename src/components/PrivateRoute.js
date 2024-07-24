import React, { useEffect, useState, useContext } from 'react';
import { Navigate, useLocation, useNavigate } from 'react-router-dom';
import { useApi } from '../api';
import { useLocalStorageKeystore } from '../services/LocalStorageKeystore';
import { fetchToken } from '../firebase';
import Layout from './Layout';
import Spinner from './Spinner'; // Import your spinner component
import { useSessionStorage } from '../components/useStorage';
import OnlineStatusContext from '../context/OnlineStatusContext';

const PrivateRoute = ({ children }) => {
	const { isOnline } = useContext(OnlineStatusContext);
	const api = useApi(isOnline);
	const [isPermissionGranted, setIsPermissionGranted] = useState(null);
	const [loading, setLoading] = useState(false);
	const keystore = useLocalStorageKeystore();
	const isLoggedIn = api.isLoggedIn() && keystore.isOpen();
	const [tokenSentInSession, setTokenSentInSession,] = api.useClearOnClearSession(useSessionStorage('tokenSentInSession', null));
	const [latestIsOnlineStatus, setLatestIsOnlineStatus,] = api.useClearOnClearSession(useSessionStorage('latestIsOnlineStatus', null));

	const location = useLocation();
	const navigate = useNavigate();

	useEffect(() => {
		const requestNotificationPermission = async () => {
			console.log(Notification.permission);

			try {
				if (Notification.permission !== 'granted') {
					setTokenSentInSession(false);
					setIsPermissionGranted(false);
					const permissionResult = await Notification.requestPermission();
					if (permissionResult === 'granted') {
						setIsPermissionGranted(true);
					}
				} else {
					setIsPermissionGranted(true);
				}
			} catch (error) {
				console.error('Error requesting notification permission:', error);
			}
		};

		if (isLoggedIn) {
			requestNotificationPermission();
		}
	}, [isLoggedIn, location]);

	useEffect(() => {
		const sendFcmTokenToBackend = async () => {
			console.log('isPermissionGranted:', isPermissionGranted);
			if (isPermissionGranted) {
				console.log('tokenSentInSession:', tokenSentInSession);

				if (!tokenSentInSession) {
					setLoading(true);
					try {
						const fcmToken = await fetchToken();
						if (fcmToken !== null) {
							await api.post('/user/session/fcm_token/add', { fcm_token: fcmToken });
							setTokenSentInSession(true)
							console.log('FCM Token success:', fcmToken);
						} else {
							console.log('FCM Token failed to get fcmtoken in private route', fcmToken);
							setTokenSentInSession(false)
						}
					} catch (error) {
						console.error('Error sending FCM token to the backend:', error);
					} finally {
						setLoading(false);
					}
				}
			}
		}

		console.log("is online = ", isOnline)
		if (isOnline) {
			sendFcmTokenToBackend();
		} else {
			setTokenSentInSession(false);
		}
	}, [isPermissionGranted, isOnline]);


	useEffect(() => {
		if (!isLoggedIn) {
			const destination = location.pathname + location.search;
			navigate('/login', { state: { from: destination } });
		}
	}, [isLoggedIn, location, navigate, isOnline]);

	// New useEffect to detect changes in isOnline status
	useEffect(() => {
		if (latestIsOnlineStatus === false && isOnline === true) {
			const performLogout = async () => {
				api.clearSession();
				await keystore.close();
				window.location.href = '/login';
			};
			performLogout();
		}
		setLatestIsOnlineStatus(isOnline);
	}, [isOnline, latestIsOnlineStatus]);

	if (!isLoggedIn) {
		return <Navigate to="/login" state={{ from: location }} replace />;
	}

	if (loading || tokenSentInSession === null) {
		return (
			<Spinner />
		)
	}
	else {
		return (
			<Layout isPermissionGranted={isPermissionGranted} tokenSentInSession={tokenSentInSession}>
				{children}
			</Layout>
		)
	}

};

export default PrivateRoute;
