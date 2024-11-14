import { ICredentialParser, ICredentialParserRegistry, ICredentialParserRegistryItem } from "../interfaces/ICredentialParser";
import { PresentationDefinitionType } from "../types/presentationDefinition.type";
import { calculateHash } from "../utils/digest";


export class CredentialParserRegistry implements ICredentialParserRegistry {

	private parserList: ICredentialParserRegistryItem[] = [];

	/**
	 * optimize parsing time by caching alread parsed objects because parse() can be called multiple times in a single view
	 */
	private parsedObjectsCache = new Map<string, { credentialFriendlyName: string; credentialImage: { credentialImageURL: string; }; beautifiedForm: any; parsedBy: string }>();

	addParser(parser: ICredentialParser, parserLabel: string): void {
		this.parserList.push({parser, parserLabel});
	}

	async parse(rawCredential: object | string, presentationDefinitionFilter?: PresentationDefinitionType) {
		const hash = await calculateHash(JSON.stringify(rawCredential));
		const cacheResult = this.parsedObjectsCache.get(hash);
		if (cacheResult) {
			return cacheResult;
		}
		const promises = this.parserList.map(async (parserItem) => {
			const parser = parserItem.parser;
			const parsed = await parser.parse(rawCredential, presentationDefinitionFilter);
			return {...parsed, parsedBy: parserItem.parserLabel}
		});

		const results = await Promise.all(promises);
		const first = results.filter((res) => ('beautifiedForm' in res))[0]; // get first successful parsing
		this.parsedObjectsCache.set(hash, first);
		return first ?? { error: "All parsings failed" };
	}

}
