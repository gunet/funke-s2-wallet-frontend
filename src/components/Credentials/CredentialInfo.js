import React, { useContext, useEffect, useState } from 'react';
import { BiSolidCategoryAlt, BiSolidUserCircle } from 'react-icons/bi';
import { AiFillCalendar } from 'react-icons/ai';
import { RiPassExpiredFill } from 'react-icons/ri';
import { MdTitle, MdGrade, MdOutlineNumbers } from 'react-icons/md';
import { GiLevelEndFlag } from 'react-icons/gi';
import { formatDate } from '../../functions/DateFormat';
import ContainerContext from '../../context/ContainerContext';
import useScreenType from '../../hooks/useScreenType';
import { IoIosInformationCircle } from "react-icons/io";

const getFieldIcon = (fieldName) => {
	switch (fieldName) {
		case 'type':
			return <BiSolidCategoryAlt size={25} className="inline mr-1" />;
		case 'expdate':
			return <RiPassExpiredFill size={25} className="inline mr-1" />;
		case 'dateOfBirth':
			return <AiFillCalendar size={25} className="inline mr-1" />;
		case 'id':
			return <MdOutlineNumbers size={25} className="inline mr-1" />;
		case 'familyName':
		case 'firstName':
			return <BiSolidUserCircle size={25} className="inline mr-1" />;
		case 'diplomaTitle':
			return <MdTitle size={25} className="inline mr-1" />;
		case 'eqfLevel':
			return <GiLevelEndFlag size={25} className="inline mr-1" />;
		case 'grade':
			return <MdGrade size={25} className="inline mr-1" />;
		default:
			return <IoIosInformationCircle size={25} className="inline mr-1" />;;
	}
};

const renderRow = (fieldName, label, fieldValue, screenType) => {

	if (fieldValue) {
		return (
			<tr className="text-left">
				<td className="font-bold text-primary dark:text-primary-light py-2 xm:py-1 px-2 rounded-l-xl">
					<div className="flex flex-row items-left">
						{screenType !== 'mobile' && getFieldIcon(fieldName)}
						<span className="md:ml-1 flex items-center">{label}:</span>
					</div>
				</td>
				<td className="text-gray-700 dark:text-white py-2 xm:py-1 px-2 rounded-r-xl">{fieldValue}</td>
			</tr>
		);
	} else {
		return null;
	}
};

const CredentialInfo = ({ credential, mainClassName = "text-sm lg:text-base w-full", display = 'mandatory' }) => {

	const [parsedCredential, setParsedCredential] = useState(null);
	const container = useContext(ContainerContext);
	const screenType = useScreenType();

	useEffect(() => {
		if (container) {
			container.credentialParserRegistry.parse(credential).then((c) => {
				if ('error' in c) {
					return;
				}
				setParsedCredential(c.beautifiedForm);
			});
		}

	}, [credential, container]);

	console.log(parsedCredential);
	return (
		<div className={mainClassName}>
			<table className="lg:w-4/5">
				<tbody className="divide-y-4 divide-transparent">
					{parsedCredential !== null && (
						<>

							{renderRow('familyName', 'Family Name', parsedCredential?.family_name, screenType)}
							{renderRow('familyName', 'Family Name Birth', parsedCredential?.family_name_birth || parsedCredential?.birth_family_name || '', screenType)}

							{renderRow('firstName', 'Given Name', parsedCredential?.given_name, screenType)}
							{renderRow('firstName', 'Legal Name', parsedCredential?.legal_name, screenType)}

							{renderRow('id', 'Personal ID', parsedCredential?.personal_identifier, screenType)}


							{renderRow('dateOfBirth', 'Birthday', formatDate(parsedCredential?.dateOfBirth, 'date'), screenType)}
							{renderRow('dateOfBirth', 'Birthday', formatDate(parsedCredential?.birth_date, 'date'), screenType)}
							{renderRow('dateOfBirth', 'Birthday', parsedCredential.birthdate, screenType)}


							{renderRow('id', 'Social Security Number', parsedCredential?.ssn, screenType)}
							{renderRow('id', 'Document Number', parsedCredential?.document_number, screenType)}
							{renderRow('id', 'Personal ID', parsedCredential?.legal_person_identifier, screenType)}

							{renderRow('', 'Issuance', parsedCredential?.iat ? formatDate(new Date(parsedCredential?.iat * 1000).toISOString()) : parsedCredential?.issuing_date ? formatDate(new Date(parsedCredential?.issuing_date.toISOString())) : parsedCredential?.issuance_date ? formatDate(new Date(parsedCredential?.issuance_date.toISOString())) : '', screenType)}
							{renderRow('expdate', 'Expiration', parsedCredential?.exp ? formatDate(new Date(parsedCredential?.exp * 1000).toISOString()) : parsedCredential?.expiry_date ? formatDate(new Date(parsedCredential?.expiry_date.toISOString())) : '', screenType)}

							{/* por */}
							{renderRow('', 'Full Powers', parsedCredential?.full_powers, screenType)}
							{renderRow('', 'Effective from', formatDate(parsedCredential?.effective_from_date), screenType)}
							{renderRow('', 'Effective until', formatDate(parsedCredential?.effective_until_date), screenType)}

							{display === 'all' && (
								<>
									{renderRow('', 'Nationality', parsedCredential?.nationality, screenType)}
									{renderRow('', 'Postal Code', parsedCredential?.resident_postal_code, screenType)}

									{renderRow('', 'Issuing Authority', parsedCredential?.issuing_authority, screenType)}

									{renderRow('', 'Resident street', parsedCredential?.resident_street, screenType)}
									{renderRow('', 'Resident country', parsedCredential?.resident_country, screenType)}
									{renderRow('', 'Resident city', parsedCredential?.resident_city, screenType)}
									{renderRow('', 'Issuing country', parsedCredential?.issuing_country, screenType)}

									{renderRow('', 'Place_of_birth', parsedCredential?.place_of_birth?.locality, screenType)}
									{renderRow('', 'Nationalities', parsedCredential?.nationalities?.join(', '), screenType)}

									{renderRow('dateOfBirth', 'Age birth year', parsedCredential.age_birth_year, screenType)}
									{renderRow('dateOfBirth', 'Age in years', parsedCredential.age_in_years, screenType)}
									{renderRow('', 'Birth Place', parsedCredential.birth_place, screenType)}

									{renderRow('', 'Address locality', parsedCredential?.address?.locality, screenType)}
									{renderRow('', 'Address country', parsedCredential?.address?.country, screenType)}
									{renderRow('', 'Address code', parsedCredential?.address?.postal_code, screenType)}
									{renderRow('', 'Address Street', parsedCredential?.address?.street_address, screenType)}

									{renderRow('', 'Age>12', parsedCredential?.age_over_12?.toString(), screenType)}
									{renderRow('', 'Age>14', parsedCredential?.age_over_14?.toString(), screenType)}
									{renderRow('', 'Age>16', parsedCredential?.age_over_16?.toString(), screenType)}
									{renderRow('', 'Age>18', parsedCredential?.age_over_18?.toString(), screenType)}
									{renderRow('', 'Age>21', parsedCredential?.age_over_21?.toString(), screenType)}
									{renderRow('', 'Age>65', parsedCredential?.age_over_65?.toString(), screenType)}

									{renderRow('', 'Age≥12', parsedCredential?.age_equal_or_over && parsedCredential?.age_equal_or_over['12'] ? parsedCredential?.age_equal_or_over['12'].toString() : null, screenType)}
									{renderRow('', 'Age≥14', parsedCredential?.age_equal_or_over && parsedCredential?.age_equal_or_over['14'] ? parsedCredential?.age_equal_or_over['14'].toString() : null, screenType)}
									{renderRow('', 'Age≥16', parsedCredential?.age_equal_or_over && parsedCredential?.age_equal_or_over['16'] ? parsedCredential?.age_equal_or_over['16'].toString() : null, screenType)}
									{renderRow('', 'Age≥18', parsedCredential?.age_equal_or_over && parsedCredential?.age_equal_or_over['18'] ? parsedCredential?.age_equal_or_over['18'].toString() : null, screenType)}
									{renderRow('', 'Age≥21', parsedCredential?.age_equal_or_over && parsedCredential?.age_equal_or_over['21'] ? parsedCredential?.age_equal_or_over['21'].toString() : null, screenType)}
								</>
							)}
						</>
					)}
				</tbody>
			</table>
		</div>
	);
};

export default CredentialInfo;
