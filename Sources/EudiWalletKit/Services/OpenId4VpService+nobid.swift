/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the European
 * Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work
 * except in compliance with the Licence.
 *
 * You may obtain a copy of the Licence at:
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software distributed under
 * the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF
 * ANY KIND, either express or implied. See the Licence for the specific language
 * governing permissions and limitations under the Licence.
 */
import Foundation
//import SwiftCBOR
//import WalletStorage
//import JOSESwift
//import SwiftyJSON
import eudi_lib_sdjwt_swift
import nobid_core


extension OpenId4VpService {
	var chosenCredentialDict: [String: Any]? {
		return chosenCredentialDict(paymentContext: NobidServiceRegistry.shared.paymentContext)
	}
	
	func chosenCredentialDict(paymentContext: NobidPaymentContext?) -> [String: Any]? {
		//return availableMsctCredentials.first?.value
		guard let paymentContext = paymentContext else {
			NobidLogger.error("BUG: paymentContext is nil in chosenCredentialDict")
			return nil
		}
		guard let docId = paymentContext.selectedMsctDocId
		else {
			NobidLogger.error("[payment-MSCT] chosenCredentialDict: 1: selectedMsctDocId is NIL")
			return nil
		}
		NobidLogger.debug("[payment-MSCT] chosenCredentialDict: 2: docId=\(docId)")
		let availableMsctCredentials = self.availableMsctCredentials
		//NobidLogger.debug("[payment-MSCT] chosenCredentialDict: 3: availableMsctCredentials.ids=\(availableMsctCredentials.keys)")
		let retVal = availableMsctCredentials[docId]
		NobidLogger.debug("[payment-MSCT] chosenCredentialDict: 4: retVal=\(String(describing: retVal))")
		return retVal
	}
	
	var availableMsctCredentials: [String: [String: Any]] {
		var retVal: [String: [String: Any]] = [:]
		do {
			//NobidLogger.debug("[payment-MSCT] availableMsctCredentials: 1: docsSdJwt.count=\(docsSdJwt?.count)")
			let parser = CompactParser()
			let docStrings = docs.filter { k,v in Self.filterFormat(dataFormats[k]!, fmt: .sdjwt)}.compactMapValues { String(data: $0, encoding: .utf8) }
			docsSdJwt = docStrings.compactMapValues { try? parser.getSignedSdJwt(serialisedString: $0) }
			//NobidLogger.debug("[payment-MSCT] availableMsctCredentials: 2: docsSdJwt.count=\(docsSdJwt.count)")
			for (docId, signedSdJwt) in docsSdJwt {
				let claimSet = signedSdJwt.claimSet
				var claimsDict = try claimSet.toDictionary()
				let disclosures = signedSdJwt.disclosures
				guard let scheme = claimsDict["scheme"] as? String, scheme == "bancomat" else {
					NobidLogger.error("[payment-MSCT] availableMsctCredentials: 3: SKIPPING credential: docId=\(docId); scheme=\(claimsDict["scheme"]); scheme MUST be \"bancomat\";")
					continue
				}
				guard let _ = claimsDict["psp"] else {
					NobidLogger.error("[payment-MSCT] availableMsctCredentials: 4: SKIPPING credential: docId=\(docId); psp NOT FOUND;")
					continue
				}
				//NobidLogger.dump("[payment-MSCT] availableMsctCredentials: 5: docId=\(docId); claimSet=\(claimSet);")
				//NobidLogger.debug("[payment-MSCT] availableMsctCredentials: 5: docId=\(docId); vct=\(claimsDict["vct"]);")
				//NobidLogger.debug("[payment-MSCT] availableMsctCredentials: 5: docId=\(docId); scheme=\(claimsDict["scheme"]);")
				//NobidLogger.dump("[payment-MSCT] availableMsctCredentials: 5: docId=\(docId); disclosures=\(disclosures);")
				//NobidLogger.dump("[payment-MSCT] availableMsctCredentials: 5: docId=\(docId); disclosures=\(disclosures.compactMap { Data(base64Encoded:$0) }.compactMap{String(data: $0, encoding: .utf8)});")
				claimsDict["docId"] = docId
				retVal[docId] = claimsDict
			}
			
			if (retVal.isEmpty) {
				NobidLogger.error("[payment-MSCT] availableMsctCredentials: 6: no available credential fits the MSCT criteria: (scheme==bancomat &&  psp=validPspMetadataUrl && format==sdJwt): returning nil")
			}
			return retVal
		}
		catch {
			NobidLogger.error("[payment-MSCT] availableMsctCredentials: 7: FAILED: error=\(error)")
			return retVal
		}
	}
}
