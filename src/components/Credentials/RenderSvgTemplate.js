import axios from 'axios';
import jsonpointer from 'jsonpointer';
import { formatDate } from '../../functions/DateFormat';

const renderSvgTemplate = async ({ beautifiedForm, credentialImageSvgTemplateURL }) => {
	let svgContent = null;
	try {
		const response = await axios.get(credentialImageSvgTemplateURL);
		if (response.status !== 200) {
			throw new Error(`Failed to fetch SVG`);
		}
		svgContent = response.data;
	} catch (error) {
		return null; // Return null if fetching fails
	}

	if (svgContent) {
		const regex = /{{([^}]+)}}/g;
		const replacedSvgText = svgContent.replace(regex, (_match, content) => {
			let res = jsonpointer.get(beautifiedForm, content.trim());
			if (res !== undefined) {
				res = formatDate(res, 'date');
				return res;
			}
			return '-';
		});
		const dataUri = `data:image/svg+xml;utf8,${encodeURIComponent(replacedSvgText)}`;
		return dataUri; // Return the data URI for the SVG
	}

	return null; // Return null if no SVG content is available
};

export default renderSvgTemplate;
