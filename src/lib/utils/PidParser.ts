import { ICredentialParser } from "../interfaces/ICredentialParser";
import { PresentationDefinitionType } from "../types/presentationDefinition.type";
import { parseSdJwtCredential } from "../../functions/parseSdJwtCredential";
import { pidData } from '../../assets/data/pid';
import renderSvgTemplate from "../../components/Credentials/RenderSvgTemplate";

export const PidParser: ICredentialParser = {
	async parse(rawCredential: object | string, presentationDefinitionFilter?: PresentationDefinitionType): Promise<{ credentialFriendlyName: string; credentialImage: { credentialImageURL: string; }; beautifiedForm: any; } | { error: string }> {

		try {
			const result = await parseSdJwtCredential(rawCredential);
			if (!result || 'error' in result) {
				return { error: "Failed to parse sdjwt" };
			}
			const vct = result.beautifiedForm.vct;
			if (vct !== "https://example.bmi.bund.de/credential/pid/1.0" && vct !== "urn:eu.europa.ec.eudi:pid:1") {
				console.log('error', 'Wrong vct');
				return { error: "Not pid parser format" };
			}

			console.log('result', result.beautifiedForm);
			// Extract relevant fields from the parsed result
			const { beautifiedForm } = result;
			if (!beautifiedForm || !beautifiedForm.vct) {
				throw new Error("Invalid format in beautifiedForm");
			}

			const credentialMetadata = pidData;
			const claims = credentialMetadata.claims;

			// Extract key values
			const credentialImageSvgTemplateURL = credentialMetadata.display[0].rendering.svg_templates[0].uri;
			const credentialFriendlyName = credentialMetadata?.name || "Credential";

			// Render SVG content
			const svgContent = await renderSvgTemplate({
				beautifiedForm: beautifiedForm,
				credentialImageSvgTemplateURL: credentialImageSvgTemplateURL,
				claims: claims
			});

			// Prepare response
			return {
				credentialFriendlyName: credentialFriendlyName || "Unknown Credential",
				credentialImage: {
					credentialImageURL: svgContent,
				},
				beautifiedForm,
			};
		} catch (e: any) {
			console.error("Error parsing credential:", e);
			return { error: e.message || JSON.stringify(e) };
		}
	},
};


