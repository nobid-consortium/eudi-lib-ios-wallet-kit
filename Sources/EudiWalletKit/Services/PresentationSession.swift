/*
Copyright (c) 2023 European Commission

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

import Foundation
import SwiftUI
import Logging
import MdocDataModel18013
import MdocDataTransfer18013
import eudi_lib_sdjwt_swift
import LocalAuthentication
import nobid_core

/// Presentation session
///
/// This class wraps the ``PresentationService`` instance, providing bindable fields to a SwifUI view
public final class PresentationSession: @unchecked Sendable, ObservableObject {
	public var presentationService: any PresentationService
	/// Reader certificate issuer (the Common Name (CN) from the verifier's certificate)
	@Published public var readerCertIssuer: String?
	/// Reader legal name (if provided)
	@Published public var readerLegalName: String?
	/// Reader certificate validation message (only for BLE transfer wih verifier using reader authentication)
	@Published public var readerCertValidationMessage: String?
	/// Reader certificate issuer is valid
	@Published public var readerCertIssuerValid: Bool?
	/// Error message when the ``status`` is in the error state.
	@Published public var uiError: WalletError?
	/// Request items selected by the user to be sent to verifier.
	@Published public var disclosedDocuments: [DocElements] = []
	/// Status of the data transfer.
	@Published public var status: TransferStatus = .initializing
	/// The ``FlowType`` instance
	// public var flow: FlowType { presentationService.flow }
	var handleSelected: ((Bool, RequestItems?) -> Void)?
	/// Device engagement data (QR data for the BLE flow)
	@Published public var deviceEngagement: String?
	// map of document id to (doc type, format, display name) pairs
	public var docIdToPresentInfo: [String: DocPresentInfo]!
	/// User authentication required
	var userAuthenticationRequired: Bool
	/// Payment context for payment-related presentation logic
	var paymentContext: NobidPaymentContext?
	/// Storage manager for accessing document models
	var storage: StorageManager?

	public init(presentationService: any PresentationService, docIdToPresentInfo: [String: DocPresentInfo], userAuthenticationRequired: Bool, paymentContext: NobidPaymentContext?, storage: StorageManager? = nil) {
		self.presentationService = presentationService
		self.docIdToPresentInfo = docIdToPresentInfo
		self.userAuthenticationRequired = userAuthenticationRequired
		self.paymentContext = paymentContext
		self.storage = storage
		NobidLogger.debug("[VP] PresentationSession.init: docIdToPresentInfo.ids=\(docIdToPresentInfo.keys.joined(separator: "  +  "))")
	}

	@MainActor
	/// Decodes a presentation request
	///
	/// The ``disclosedDocuments`` property will be set. Additionally ``readerCertIssuer`` and ``readerCertValidationMessage`` may be set
	/// - Parameter request: Request information
	func decodeRequest(_ request: UserRequestInfo) throws {
		NobidLogger.debug("PresentationSession.decodeRequest: 1: ENTER: request=\(request)")
		guard docIdToPresentInfo.count > 0 else { 
			NobidLogger.taskFailed("Consent: no documents to choose from: docIdToPresentInfo is EMPTY")
			NobidLogger.error("PresentationSession.decodeRequest: 2: FAILED: docIdToPresentInfo is empty")
			throw Self.makeError(str: "No documents added to session ")
		}
		NobidLogger.debug("[consent] building disclosedDocuments")
		NobidLogger.debug("********************************************************************")
		NobidLogger.debug(" REQUESTED CONDITIONS:")
		NobidLogger.debug(" Requested formats:")
		NobidLogger.debug(" \(request.docDataFormats.map{ String(" * \($0): \($1)\n") }.joined())")
		NobidLogger.debug(" Requested items:")
		NobidLogger.debug(" \(request.itemsRequested.map{ String(" * \($0): \($1.map{key, val in val.map{ $0.elementIdentifier }.joined(separator: " ") } )\n") }.joined())")
		NobidLogger.debug("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  - - - -")
		NobidLogger.debug(" AVAILABLE DOCUMENTS:")
		NobidLogger.debug("")

		for (docId, docPresentInfo) in docIdToPresentInfo {
			let docType = docPresentInfo.docType
			let requestFormat = request.docDataFormats[docId] ?? request.docDataFormats[docType]  ?? request.docDataFormats.first(where: { Openid4VpUtils.vctToDocTypeMatch($0.key, docType)})?.value
			let formatSame = requestFormat == docPresentInfo.docDataFormat
			NobidLogger.debug(" * \(docId)")
			NobidLogger.debug("   name=\(docPresentInfo.displayName ?? "")")
			NobidLogger.debug("   docType=\(docPresentInfo.docType)")

			if let paymentContext = paymentContext, let selectedMsctDocId = paymentContext.selectedMsctDocId {
				if docId != selectedMsctDocId {
//					NobidLogger.debug("   SKIPPED because MSCT is identified and this docId doesn't match the selectedMsctDocId=\(selectedMsctDocId)")
//					continue
				}
				else {
					NobidLogger.debug("   MSCT is identified BUT selectedMsctDocId=\(selectedMsctDocId) is NOT A2Pay: extra credential?")
				}
			}
			
			if (requestFormat == nil) {
				NobidLogger.debug("")
				NobidLogger.debug("   requestFormat is NIL !!!!")
				NobidLogger.debug("    -> check \"Requested formats\" keys above for these values:")
				NobidLogger.debug("      docId=\(docId)")
				NobidLogger.debug("      docType=\(docType)")
				NobidLogger.debug("      vctToDocType=\(Openid4VpUtils.vctToDocType(docType))")
				NobidLogger.debug("")
				continue
			}
			
			switch requestFormat {
				case .cbor:
					var isTypedDataMsoMdoc = false
					if case let .msoMdoc(issuerSigned) = docPresentInfo.typedData {
						isTypedDataMsoMdoc = true
					}
					NobidLogger.debug("   typedData=msoMdoc; match=\(isTypedDataMsoMdoc)")
					if (isTypedDataMsoMdoc == false) {
						NobidLogger.debug("     -> msoMdoc is only valid for CBOR. Currently requested is SDJWT")
					}
					var isSameDocItemsRequested = false
					if let docItemsRequested = request.itemsRequested[docId] ?? request.itemsRequested[docType] {
						isSameDocItemsRequested = true
					}
					NobidLogger.debug("   itemsRequested are present=\(isSameDocItemsRequested)\(isSameDocItemsRequested ? "" : "!!!!")")
					//					let msoElements = issuerSigned.extractMsoMdocElements(docId: docId, docType: docType, displayName: docPresentInfo.displayName, docClaims: docPresentInfo.docClaims, itemsRequested: docItemsRequested)
					//disclosedDocuments.append(.msoMdoc(msoElements))
				case .sdjwt:
					var isTypedDataSdJwt = false
				var signedSdJwt: SignedSDJWT?
					if case let .sdJwt(_signedSdJwt) = docPresentInfo.typedData {
						signedSdJwt = _signedSdJwt
						isTypedDataSdJwt = true
					}
					NobidLogger.debug("   typedData=sdjwt; match=\(isTypedDataSdJwt)")
					if (isTypedDataSdJwt == false) {
						NobidLogger.debug("     -> sdjwt is only valid for SDJWT. Currently requested is CBOR")
					}
					var isSameDocItemsRequested = false
					if let sdItemsRequested = request.itemsRequested[docId] ?? request.itemsRequested[docType]
						, let sdJwtElements = signedSdJwt?.extractSdJwtElements(docId: docId, vct: docType, displayName: docPresentInfo.displayName, docClaims: docPresentInfo.docClaims, itemsRequested: sdItemsRequested) {
						isSameDocItemsRequested = true
					}
					NobidLogger.debug("   itemsRequested are present=\(isSameDocItemsRequested)\(isSameDocItemsRequested ? "" : "!!!!")")
					//disclosedDocuments.append(.sdJwt(sdJwtElements))
				default:
					NobidLogger.debug("   UNSUPPORTED requestFormat \(requestFormat)")
			}
			NobidLogger.debug("")
		}
		NobidLogger.debug("********************************************************************")

		// show the items as checkboxes
		disclosedDocuments = [DocElements]()
		for (docId, docPresentInfo) in docIdToPresentInfo {
			NobidLogger.debug("PresentationSession.decodeRequest: 3: docId=\(docId)")
			let docType = docPresentInfo.docType
			let requestFormat = request.docDataFormats[docId] ?? request.docDataFormats[docType]  ?? request.docDataFormats.first(where: { Openid4VpUtils.vctToDocTypeMatch($0.key, docType)})?.value
			if requestFormat != docPresentInfo.docDataFormat  { continue }
			switch requestFormat {
				case .cbor:
					NobidLogger.debug("PresentationSession.decodeRequest: 3: case .cbor")
					guard case let .msoMdoc(issuerSigned) = docPresentInfo.typedData else { continue }
					guard let docItemsRequested = request.itemsRequested[docId] ?? request.itemsRequested[docType] else { continue }
					let msoElements = issuerSigned.extractMsoMdocElements(docId: docId, docType: docType, displayName: docPresentInfo.displayName, docClaims: docPresentInfo.docClaims, itemsRequested: docItemsRequested)
					disclosedDocuments.append(.msoMdoc(msoElements))
				case .sdjwt:
					NobidLogger.debug("PresentationSession.decodeRequest: 4: case .sdjwt")
					guard case let .sdJwt(signedSdJwt) = docPresentInfo.typedData else { continue }
					guard let sdItemsRequested = request.itemsRequested[docId] ?? request.itemsRequested[docType] else { continue }
					let sdJwtElements = signedSdJwt.extractSdJwtElements(docId: docId, vct: docType, displayName: docPresentInfo.displayName, docClaims: docPresentInfo.docClaims, itemsRequested: sdItemsRequested)
					guard let sdJwtElements else { continue }
					disclosedDocuments.append(.sdJwt(sdJwtElements))
				default: 
					NobidLogger.error("PresentationSession.decodeRequest: 5: Unsupported format \(docPresentInfo.docDataFormat) for \(docId)")
			}
		}
		
		if let readerAuthority = request.readerCertificateIssuer {
			readerCertIssuer = readerAuthority
			readerCertIssuerValid = request.readerAuthValidated
			readerCertValidationMessage = request.readerCertificateValidationMessage
		}
		readerLegalName = request.readerLegalName
		status = .requestReceived

		guard let paymentContext = paymentContext else {
			NobidLogger.error("[paymentTransaction][payment-MSCT][paymentStatus] QUIT: BUG: paymentContext is nil, skipping payment flow logic")
			return
		}
		
		if (paymentContext.isPaymentFlow) {
			if (disclosedDocuments.count > 1) {
				NobidLogger.debug("[consent][payment] MORE THAN ONE credential IDENTIFIED. Checking for muliple payment credentials...")
				let paymentMsctDocs = disclosedDocuments.filter { doc in doc.isPaymentMSCT }
				if (paymentMsctDocs.count > 1 && paymentContext.selectedMsctDocId == nil) {
					NobidLogger.error("[consent][payment] BUG: MORE THAN ONE MSCT payment credential IDENTIFIED & selectedMsctDocId is NIL! This should be handled already just after qrCode was scanned. Check the code! Will yuse the first one now.")
					NobidLogger.debug("[consent][payment] disclosedDocuments.count=\(disclosedDocuments.count); paymentMsctDocs.count=\(paymentMsctDocs.count)")
					let firstDoc = paymentMsctDocs.first
					disclosedDocuments.removeAll(where: { doc in doc.isPaymentMSCT && doc.id != firstDoc?.id })
					NobidLogger.debug("[consent][payment] AFTER corretion: disclosedDocuments.count=\(disclosedDocuments.count);")
				}
				else if (paymentMsctDocs.count > 1) {
					NobidLogger.debug("[consent][payment] MORE THAN ONE MSCT payment credential IDENTIFIED. Will use selectedMsctDocId=\(paymentContext.selectedMsctDocId ?? "nil")")
					NobidLogger.debug("[consent][payment] disclosedDocuments.count=\(disclosedDocuments.count); paymentMsctDocs.count=\(paymentMsctDocs.count)")
					let firstDoc = paymentMsctDocs.first { doc in doc.id == paymentContext.selectedMsctDocId }
					disclosedDocuments.removeAll(where: { doc in doc.isPaymentMSCT && doc.id != firstDoc?.id })
					NobidLogger.debug("[consent][payment] AFTER corretion: disclosedDocuments.count=\(disclosedDocuments.count);")
				}
				let paymentOtherDocs = disclosedDocuments.filter { doc in doc.isPaymentOther }
				if (paymentOtherDocs.count > 1) {
					NobidLogger.debug("[consent][payment] MORE THAN ONE non-MSCT payment credential IDENTIFIED. Will use the first one. <M> implement docPicker if needed.")
					NobidLogger.debug("[consent][payment] disclosedDocuments.count=\(disclosedDocuments.count); paymentOtherDocs.count=\(paymentOtherDocs.count)")
					let firstDoc = paymentOtherDocs.first
					disclosedDocuments.removeAll(where: { doc in doc.isPaymentOther && doc.id != firstDoc?.id })
					NobidLogger.debug("[consent][payment] AFTER corretion: disclosedDocuments.count=\(disclosedDocuments.count);")
				}
			}

			if (paymentContext.selectedMsctDocId == nil) {
				let paymentOtherDocs = disclosedDocuments.filter { doc in doc.isPaymentOther }
				paymentContext.selectedMsctDocId = paymentOtherDocs.first?.id
				NobidLogger.debug("[consent][paymentTransaction][paymentStatus] DSVG QUICK-FIX APPLIED: transactionData FOUND thus assuming payment transaction; setting  selectedMsctDocId=\(paymentContext.selectedMsctDocId ?? "nil")")
			}
			if paymentContext.selectedDocIconUri == nil, let docId = paymentContext.selectedMsctDocId {
				let doc: DocClaimsDecodable? = storage?.getDocumentModel(id: docId)
				let dd: DisplayMetadata? = doc?.issuerDisplay?.first
				let uri = dd?.logo?.uri
				let contextToModify = paymentContext
				contextToModify.selectedDocIconUri = uri
				NobidLogger.debug("[payment] selectedDocIconUri=\(contextToModify.selectedDocIconUri?.absoluteString ?? "nil")")
			}
		}

		if (disclosedDocuments.isEmpty == true) {
			NobidLogger.taskFailed("[consent][paymentTransaction][payment-MSCT][paymentStatus] NO documents which meets request criteria. See details above!")
		}
		else {
			disclosedDocuments.sort { doc1, doc2 in
				return doc1.isPaymentMSCT || doc1.isPaymentOther
			}
			NobidLogger.taskSucceed("[consent] FOUND \(disclosedDocuments.count) documents for disclosure list.")
			NobidLogger.debug("[consent] disclosedDocuments: \(disclosedDocuments.map { String("\($0.id): \($0.docTypeOrVct)") }.joined(separator: ", "))")
			NobidLogger.debug("[consent] NOTE: disclosedDocuments count may change later on if requested items are not present in the document! Check the logs for: [consent] onRequestReceived:")
		}
	}

	public static func makeError(str: String) -> NSError {
		logger.error(Logger.Message(unicodeScalarLiteral: str))
		return NSError(domain: "\(PresentationSession.self)", code: 0, userInfo: [NSLocalizedDescriptionKey: str])
	}

	public static func makeError(code: MdocDataTransfer18013.ErrorCode, str: String? = nil) -> NSError {
		let message = str ?? code.description
		logger.error(Logger.Message(unicodeScalarLiteral: message))
		return NSError(domain: "\(PresentationSession.self)", code: 0, userInfo: [NSLocalizedDescriptionKey: message])
	}

	/// Start QR engagement to be presented to verifier
	///
	/// On success ``deviceEngagement`` published variable will be set with the result and ``status`` will be ``.qrEngagementReady``
	/// On error ``uiError`` will be filled and ``status`` will be ``.error``
	public func startQrEngagement() async {
		NobidLogger.debug("PresentationSession.startQrEngagement: 1: ENTER")
		do {
			let data = try await presentationService.startQrEngagement(secureAreaName: nil, crv: .P256)
			NobidLogger.debug("PresentationSession.startQrEngagement: 2: data=\(data)")
			await MainActor.run {
				deviceEngagement = data
				status = .qrEngagementReady
			}
		} catch { 
			NobidLogger.error("PresentationSession.startQrEngagement: 3: FAILED: \(error.localizedDescription)")
			await setError(error) 
		}
	}

	@MainActor
	func setError(_ error: Error) {
		NobidLogger.error("setError: 1: FAILED: \(error.localizedDescription)")
		status = .error
		uiError = WalletError(description: error.localizedDescription, userInfo: (error as NSError).userInfo)
	}

	/// Receive request from verifer
	///
	/// The request is futher decoded internally. See also ``decodeRequest(_:)``
	/// On success ``disclosedDocuments`` published variable will be set  and ``status`` will be ``.requestReceived``
	/// On error ``uiError`` will be filled and ``status`` will be ``.error``
	/// - Returns: A request object
	public func receiveRequest() async -> UserRequestInfo? {
		NobidLogger.debug("PresentationSession.receiveRequest: 1: ENTER")
		do {
			let request = try await presentationService.receiveRequest()
			NobidLogger.debug("PresentationSession.receiveRequest: 2: request=\(request)")
			try await decodeRequest(request)
			return request
		} catch {
			NobidLogger.error("PresentationSession.receiveRequest: 3: FAILED: \(error.localizedDescription)")
			await setError(error)
			return nil
		}
	}

	/// Send response to verifier
	/// - Parameters:
	///   - userAccepted: Whether user confirmed to send the response
	///   - itemsToSend: Data to send organized into a hierarcy of doc.types and namespaces
	///   - onCancel: Action to perform if the user cancels the biometric authentication
	public func sendResponse(userAccepted: Bool, itemsToSend: RequestItems, onCancel: (() -> Void)? = nil, onSuccess: (@Sendable (URL?) -> Void)? = nil) async {
		NobidLogger.debug("PresentationSession.sendResponse: 1: ENTER: userAccepted=\(userAccepted)")
		do {
			await MainActor.run {status = .userSelected }
			let action = { [ weak self] in 
				NobidLogger.debug("PresentationSession.sendResponse: 2: action")
				_ = try await self?.presentationService.sendResponse(userAccepted: userAccepted, itemsToSend: itemsToSend, onSuccess: onSuccess) 
			}
			try await EudiWallet.authorizedAction(action: action, disabled: !userAuthenticationRequired, dismiss: { onCancel?()}, localizedReason: NSLocalizedString("authenticate_to_share_data", comment: "") )
			await MainActor.run {status = .responseSent }
		} catch { 
			NobidLogger.error("PresentationSession.sendResponse: 3: FAILED: \(error.localizedDescription)")
			await setError(error) 
		}
	}
}

