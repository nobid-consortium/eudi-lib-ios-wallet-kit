/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import Foundation
@preconcurrency import OpenID4VCI
import JOSESwift
import MdocDataModel18013
import AuthenticationServices
import Logging
import CryptoKit
import Security
import WalletStorage
import SwiftCBOR
import JOSESwift
import nobid_core

extension CredentialIssuerSource: @retroactive @unchecked Sendable {}

public final class OpenId4VCIService: NSObject, @unchecked Sendable, ASWebAuthenticationPresentationContextProviding {
	let issueReq: IssueRequest
	let credentialIssuerURL: String
	let uiCulture: String?
	var bindingKey: BindingKey!
	let logger: Logger
	let config: OpenId4VCIConfig
	static var metadataCache = [String: CredentialOffer]()
	var urlSession: URLSession
	var parRequested: ParRequested?
	let configurationContext: NobidConfigurationContext
	private let signerService: NobidSignerService

	init(issueRequest: IssueRequest, credentialIssuerURL: String, uiCulture: String?, config: OpenId4VCIConfig, urlSession: URLSession, configurationContext: NobidConfigurationContext, signerService: NobidSignerService) {
		self.issueReq = issueRequest
		self.credentialIssuerURL = credentialIssuerURL
		self.uiCulture = uiCulture
		self.urlSession = urlSession
		logger = Logger(label: "OpenId4VCI")
		self.config = config
		self.configurationContext = configurationContext
		self.signerService = signerService
	}

	func initSecurityKeys(algSupported: Set<String>) async throws {
        NobidLogger.debug("Step: initSecurityKeys: 1: algSupported=\(algSupported)")
		let crvType = issueReq.keyOptions?.curve ?? type(of: issueReq.secureArea).defaultEcCurve
		let secureAreaSigningAlg: SigningAlgorithm = crvType.defaultSigningAlgorithm
		let algTypes = algSupported.compactMap { JWSAlgorithm.AlgorithmType(rawValue: $0) }
        NobidLogger.debug("Step: initSecurityKeys: 2: algTypes=\(algTypes)")
        if algTypes.isEmpty {
            NobidLogger.error("Step: initSecurityKeys: 2: algSupported IS EMPTY: See CredentialConfiguration.credentialSigningAlgValuesSupported (credential_signing_alg_values_supported) in metadata: .well-known/openid-credential-issuer")
        }
		guard !algTypes.isEmpty, let algType = JWSAlgorithm.AlgorithmType(rawValue: secureAreaSigningAlg.rawValue), algTypes.contains(algType) else {
            NobidLogger.error("Step: initSecurityKeys: 3: Unable to find supported signing algorithm: \(secureAreaSigningAlg)")
            NobidLogger.error("Step: initSecurityKeys: 3: See CredentialConfiguration.credentialSigningAlgValuesSupported (credential_signing_alg_values_supported) in metadata: .well-known/openid-credential-issuer")
			throw WalletError(description: "Unable to find supported signing algorithm \(secureAreaSigningAlg)")
		}
		let publicCoseKey = try await issueReq.createKey()
        NobidLogger.debug("Step: initSecurityKeys: 4: publicCoseKey=\(publicCoseKey)")
		let publicKey: SecKey = try publicCoseKey.toSecKey()
        NobidLogger.debug("Step: initSecurityKeys: 5: publicKey=\(publicKey)")
		let publicKeyJWK = try ECPublicKey(publicKey: publicKey, additionalParameters: ["alg": JWSAlgorithm(algType).name, "use": "sig", "kid": UUID().uuidString])
        NobidLogger.debug("Step: initSecurityKeys: 6: publicKeyJWK=\(publicKeyJWK)")
		let unlockData = try await issueReq.secureArea.unlockKey(id: issueReq.id)
        NobidLogger.debug("Step: initSecurityKeys: 7: unlockData=\(unlockData?.count)")
		let signer = try SecureAreaSigner(secureArea: issueReq.secureArea, id: issueReq.id, ecAlgorithm: secureAreaSigningAlg, unlockData: unlockData)
		bindingKey = .jwk(algorithm: JWSAlgorithm(algType), jwk: publicKeyJWK, privateKey: .custom(signer) , issuer: config.client.id)
	}

	func setBindingKey(bindingKey: BindingKey) {
		self.bindingKey = bindingKey
	}

	static func removeOfferFromMetadata(offerUri: String) {
		Self.metadataCache.removeValue(forKey: offerUri)
	}

	/// Issue a document with the given `docType` or `scope` or `identifier` using OpenId4Vci protocol
	/// - Parameters:
	///   - docType: the docType of the document to be issued
	///   - scope: the scope of the document to be issued
	///   - identifier: the credential configuration identifier of the document to be issued
	/// - Returns: The data of the document
	func issueDocument(docType: String?, scope: String?, identifier: String?, promptMessage: String? = nil) async throws -> (IssuanceOutcome, DocDataFormat) {
		guard let docTypeOrScopeOrIdentifier = docType ?? scope ?? identifier else { throw WalletError(description: "docType or scope or identifier must be provided") }
		logger.log(level: .info, "Issuing document with \(docType != nil ? "docType" : scope != nil ? "scope" : "identifier"): \(docTypeOrScopeOrIdentifier)")
		let res = try await issueByDocType(docType, scope: scope, identifier: identifier, promptMessage: promptMessage)
		return res
	}

	/// Resolve issue offer and return available document metadata
	/// - Parameters:
	///   - uriOffer: Uri of the offer (from a QR or a deep link)
	///   - format: format of the exchanged data
	/// - Returns: The data of the document
	public func resolveOfferDocTypes(uriOffer: String) async throws -> OfferedIssuanceModel {
		let result = await CredentialOfferRequestResolver(fetcher: Fetcher(session: urlSession), credentialIssuerMetadataResolver: CredentialIssuerMetadataResolver(fetcher: Fetcher(session: urlSession)), authorizationServerMetadataResolver: AuthorizationServerMetadataResolver(oidcFetcher: Fetcher(session: urlSession), oauthFetcher: Fetcher(session: urlSession))).resolve(source: try .init(urlString: uriOffer))
		switch result {
		case .success(let offer):
			let code: Grants.PreAuthorizedCode? = switch offer.grants {	case .preAuthorizedCode(let preAuthorizedCode): preAuthorizedCode; case .both(_, let preAuthorizedCode): preAuthorizedCode; case .authorizationCode(_), .none: nil	}
            NobidLogger.debug("Step: VCI: processOfferRequest: resolveOfferDocTypes: PreAuthorizedCode=\(code?.preAuthorizedCode ?? "nil")")
            NobidLogger.debug("Step: VCI: processOfferRequest: resolveOfferDocTypes: offer.credentialIssuerMetadata.credentialsSupported=\(offer.credentialIssuerMetadata.credentialsSupported.keys.map{$0.value}.joined(separator: "-"))")
            NobidLogger.debug("Step: VCI: processOfferRequest: resolveOfferDocTypes: offer.credentialConfigurationIdentifiers=\(offer.credentialConfigurationIdentifiers.map{$0.value}.joined(separator: "-"))")
			Self.metadataCache[uriOffer] = offer
			let credentialInfo = try getCredentialIdentifiers(credentialsSupported: offer.credentialIssuerMetadata.credentialsSupported.filter { offer.credentialConfigurationIdentifiers.contains($0.key) })
			let issuerName = offer.credentialIssuerMetadata.display.getName(uiCulture) ?? offer.credentialIssuerIdentifier.url.host ?? offer.credentialIssuerIdentifier.url.absoluteString.replacingOccurrences(of: "https://", with: "")
			let issuerLogoUrl = offer.credentialIssuerMetadata.display.getLogo(uiCulture)?.uri?.absoluteString
			return OfferedIssuanceModel(issuerName: issuerName, issuerLogoUrl: issuerLogoUrl, docModels: credentialInfo.map(\.offered), txCodeSpec:  code?.txCode)
		case .failure(let error):
			throw WalletError(description: "Unable to resolve credential offer: \(error.localizedDescription)")
		}
	}

	func getIssuer(offer: CredentialOffer) throws -> Issuer {
		try Issuer(authorizationServerMetadata: offer.authorizationServerMetadata, issuerMetadata: offer.credentialIssuerMetadata, config: config, parPoster: Poster(session: urlSession), tokenPoster: Poster(session: urlSession), requesterPoster: Poster(session: urlSession), deferredRequesterPoster: Poster(session: urlSession), notificationPoster: Poster(session: urlSession), isIPSZflow: configurationContext.isIPSZflow, signerService: signerService)
	}

	func getIssuerForDeferred(data: DeferredIssuanceModel) throws -> Issuer {
		try Issuer.createDeferredIssuer(deferredCredentialEndpoint: data.deferredCredentialEndpoint, deferredRequesterPoster: Poster(session: urlSession), config: config, isIPSZflow: configurationContext.isIPSZflow, signerService: signerService)
	}

	func authorizeOffer(offerUri: String, docTypeModels: [OfferedDocModel], txCodeValue: String?) async throws -> (AuthorizeRequestOutcome, [CredentialConfiguration]) {
        NobidLogger.debug("Step: authorizeOffer: 1: offerUri=\(offerUri)")
		guard let offer = Self.metadataCache[offerUri] else { throw WalletError(description: "offerUri not resolved. resolveOfferDocTypes must be called first")}
        NobidLogger.debug("Step: authorizeOffer: 2: offer=\(offer.credentialConfigurationIdentifiers.map{$0.value}.joined(separator: "-"))")
		let credentialInfos = docTypeModels.compactMap { try? getCredentialIdentifier(credentialIssuerIdentifier: offer.credentialIssuerIdentifier.url.absoluteString.replacingOccurrences(of: "https://", with: ""), issuerDisplay: offer.credentialIssuerMetadata.display, credentialsSupported: offer.credentialIssuerMetadata.credentialsSupported, identifier: $0.credentialConfigurationIdentifier, docType: $0.docType, scope: $0.scope) }
		guard credentialInfos.count > 0, credentialInfos.count == docTypeModels.count else { throw WalletError(description: "Missing Credential identifiers") }
        NobidLogger.debug("Step: authorizeOffer: 3: credentialInfos=\(credentialInfos.count)")
		try await initSecurityKeys(algSupported: Set(credentialInfos.flatMap { $0.algValuesSupported }))
        NobidLogger.debug("Step: authorizeOffer: 4: initSecurityKeys done")
		let code: Grants.PreAuthorizedCode? = switch offer.grants {	case .preAuthorizedCode(let preAuthorizedCode):	preAuthorizedCode; case .both(_, let preAuthorizedCode):	preAuthorizedCode; case .authorizationCode(_), .none: nil	}
		let txCodeSpec: TxCode? = code?.txCode
		let preAuthorizedCode: String? = code?.preAuthorizedCode
		let issuer = try getIssuer(offer: offer)
		if preAuthorizedCode != nil && txCodeSpec != nil && txCodeValue == nil { throw WalletError(description: "A transaction code is required for this offer") }
		let authorizedOutcome = if let preAuthorizedCode, let authCode = try? IssuanceAuthorization(preAuthorizationCode: preAuthorizedCode, txCode: txCodeSpec) { AuthorizeRequestOutcome.authorized(try await issuer.authorizeWithPreAuthorizationCode(credentialOffer: offer, authorizationCode: authCode, client: config.client, transactionCode: txCodeValue).get()) } else { try await authorizeRequestWithAuthCodeUseCase(issuer: issuer, offer: offer) }
		return (authorizedOutcome, credentialInfos)
	}

	func issueDocumentByOfferUrl(offer: CredentialOffer, authorizedOutcome: AuthorizeRequestOutcome, configuration: CredentialConfiguration, promptMessage: String? = nil, claimSet: ClaimSet? = nil) async throws -> IssuanceOutcome? {
		NobidLogger.taskSucceed("case: issuance by offer: scanned QR code?")
		if case .presentation_request(let url) = authorizedOutcome, let parRequested {
			logger.info("Dynamic issuance request with url: \(url)")
			let uuid = UUID().uuidString
			Self.metadataCache[uuid] = offer
			return .pending(PendingIssuanceModel(pendingReason: .presentation_request_url(url.absoluteString), configuration: configuration, metadataKey: uuid, pckeCodeVerifier: parRequested.pkceVerifier.codeVerifier, pckeCodeVerifierMethod: parRequested.pkceVerifier.codeVerifierMethod ))
		}
		guard case .authorized(let authorized) = authorizedOutcome else { throw WalletError(description: "Invalid authorized request outcome") }
		do {
			let id = configuration.configurationIdentifier.value; let sc = configuration.scope; let dn = configuration.display.getName(uiCulture) ?? ""
			logger.info("Starting issuing with identifer \(id), scope \(sc), displayName: \(dn)")
			let issuer = try getIssuer(offer: offer)
			let res = try await issueOfferedCredentialInternalValidated(authorized, offer: offer, issuer: issuer, configuration: configuration, claimSet: claimSet)
			// logger.info("Credential str:\n\(str)")
			return res
		} catch {
			// logger.error("Failed to issue document with scope \(ci.scope)")
			logger.info("Exception: \(error)")
			return nil
		}
	}

	func issueByDocType(_ docType: String?, scope: String?, identifier: String?, promptMessage: String? = nil, claimSet: ClaimSet? = nil) async throws -> (IssuanceOutcome, DocDataFormat) {
		NobidLogger.taskSucceed("case: issuance device originated: doc type selected from the list: docType=\(docType ?? "nil"), scope=\(scope ?? "nil"), identifier=\(identifier ?? "nil")")
        NobidLogger.debug("VP: issueByDocType: 1: docType=\(docType ?? "nil"); identifier=\(identifier ?? "nil"); scope=\(scope ?? "nil")")
		let credentialIssuerIdentifier = try CredentialIssuerId(credentialIssuerURL)
        NobidLogger.debug("VP: issueByDocType: 2:")
		let issuerMetadata = await CredentialIssuerMetadataResolver(fetcher: Fetcher(session: urlSession)).resolve(source: .credentialIssuer(credentialIssuerIdentifier))
        NobidLogger.debug("VP: issueByDocType: 3: issuerMetadata fetched")
		switch issuerMetadata {
		case .success(let metaData):
            NobidLogger.debug("VP: issueByDocType: 4: success")
			if let authorizationServer = metaData.authorizationServers?.first {
                NobidLogger.debug("VP: issueByDocType: 5: authorizationServer=\(authorizationServer)")
				let authServerMetadata = await AuthorizationServerMetadataResolver(oidcFetcher: Fetcher(session: urlSession), oauthFetcher: Fetcher(session: urlSession)).resolve(url: authorizationServer)
				let configuration = try getCredentialIdentifier(credentialIssuerIdentifier: credentialIssuerIdentifier.url.absoluteString.replacingOccurrences(of: "https://", with: ""), issuerDisplay: metaData.display, credentialsSupported: metaData.credentialsSupported, identifier: identifier, docType: docType, scope: scope)
                NobidLogger.debug("VP: issueByDocType: 6:")
				try await initSecurityKeys(algSupported: Set(configuration.algValuesSupported))
                NobidLogger.debug("VP: issueByDocType: 7: initSecurityKeys done")
				let offer = try CredentialOffer(credentialIssuerIdentifier: credentialIssuerIdentifier, credentialIssuerMetadata: metaData, credentialConfigurationIdentifiers: [configuration.configurationIdentifier], grants: nil, authorizationServerMetadata: try authServerMetadata.get())
				// Authorize with auth code flow
                NobidLogger.debug("VP: issueByDocType: 8: offer created")
				let issuer = try getIssuer(offer: offer)
                NobidLogger.debug("VP: issueByDocType: 9: issuer created")
				let authorizedOutcome = try await authorizeRequestWithAuthCodeUseCase(issuer: issuer, offer: offer)
                NobidLogger.debug("VP: issueByDocType: 10: authorizedOutcome created")
				if case .presentation_request(let url) = authorizedOutcome, let parRequested {
                    NobidLogger.debug("VP: issueByDocType: 11: case .presentation_request")
					logger.info("Dynamic issuance request with url: \(url)")
					let uuid = UUID().uuidString
					Self.metadataCache[uuid] = offer
					let outcome = IssuanceOutcome.pending(PendingIssuanceModel(pendingReason: .presentation_request_url(url.absoluteString), configuration: configuration, metadataKey: uuid, pckeCodeVerifier: parRequested.pkceVerifier.codeVerifier, pckeCodeVerifierMethod: parRequested.pkceVerifier.codeVerifierMethod ))
                    NobidLogger.debug("VP: issueByDocType: 12:")
					return (outcome, configuration.format)
				}
				guard case .authorized(let authorized) = authorizedOutcome else {
                    NobidLogger.error("VP: issueByDocType: 13: Invalid authorized request outcome")
                    throw WalletError(description: "Invalid authorized request outcome") }
				let outcome = try await issueOfferedCredentialInternal(authorized, issuer: issuer, configuration: configuration, claimSet: claimSet)
                NobidLogger.debug("VP: issueByDocType: 14:")
				return (outcome, configuration.format)
			} else {
                NobidLogger.error("VP: issueByDocType: 15: Invalid authorization server")
				throw WalletError(description: "Invalid authorization server")
			}
		case .failure:
            NobidLogger.error("VP: issueByDocType: 16: failed: Invalid issuer metadata")
			throw WalletError(description: "Invalid issuer metadata")
		}
	}

	private func issueOfferedCredentialInternal(_ authorized: AuthorizedRequest, issuer: Issuer, configuration: CredentialConfiguration, claimSet: ClaimSet?) async throws -> IssuanceOutcome {
		switch authorized {
		case .noProofRequired:
			NobidLogger.taskSucceed("Issuance: noProofRequired identified")
			return try await noProofRequiredSubmissionUseCase(issuer: issuer, noProofRequiredState: authorized, configuration: configuration, claimSet: claimSet)
		case .proofRequired:
			NobidLogger.taskSucceed("Issuance: proofRequired identified")
			return try await proofRequiredSubmissionUseCase(issuer: issuer, authorized: authorized, configuration: configuration, claimSet: claimSet)
		}
	}

	private func issueOfferedCredentialInternalValidated(_ authorized: AuthorizedRequest, offer: CredentialOffer, issuer: Issuer, configuration: CredentialConfiguration, claimSet: ClaimSet? = nil) async throws -> IssuanceOutcome {
		let issuerMetadata = offer.credentialIssuerMetadata
		guard issuerMetadata.credentialsSupported.keys.contains(where: { $0.value == configuration.configurationIdentifier.value }) else {
			throw WalletError(description: "Cannot find credential identifier \(configuration.configurationIdentifier.value) in offer")
		}
		return try await issueOfferedCredentialInternal(authorized, issuer: issuer, configuration: configuration, claimSet: claimSet)
	}

	func getCredentialIdentifier(credentialIssuerIdentifier: String, issuerDisplay: [Display], credentialsSupported: [CredentialConfigurationIdentifier: CredentialSupported], identifier: String?, docType: String?, scope: String?) throws -> CredentialConfiguration {
			if let credential = credentialsSupported.first(where: { if case .msoMdoc(let msoMdocCred) = $0.value, msoMdocCred.docType == docType || docType == nil, $0.key.value == identifier || identifier == nil { true } else { false } }), case let .msoMdoc(msoMdocConf) = credential.value, let scope = msoMdocConf.scope {
			logger.info("msoMdoc with scope \(scope), cryptographic suites: \(msoMdocConf.credentialSigningAlgValuesSupported)")
                NobidLogger.debug("issueDoc: getCredentialIdentifier: format=msoMdoc; scope=\(scope); credentialSigningAlgValuesSupported=\(msoMdocConf.credentialSigningAlgValuesSupported); proofTypesSupported=\(msoMdocConf.proofTypesSupported?["jwt"]?.algorithms ?? [])")
                if (msoMdocConf.proofTypesSupported?["jwt"]?.algorithms.isEmpty ?? true) {
                    NobidLogger.error("issueDoc: getCredentialIdentifier: jwt.proofTypesSupported IS EMPTY: See jwt/proof_types_supported in metadata: .well-known/openid-credential-issuer")
                }
				return CredentialConfiguration(configurationIdentifier: credential.key, credentialIssuerIdentifier: credentialIssuerIdentifier, docType: docType, scope: scope, display: msoMdocConf.display.map(\.displayMetadata), issuerDisplay: issuerDisplay.map(\.displayMetadata), algValuesSupported: msoMdocConf.proofTypesSupported?["jwt"]?.algorithms ?? [], msoClaims: msoMdocConf.claims, flatClaims: nil, order: msoMdocConf.order, format: .cbor)
		} else if let credential =  credentialsSupported.first(where: { if case .sdJwtVc(let sdJwtVc) = $0.value, sdJwtVc.scope == scope || scope == nil, $0.key.value == identifier || identifier == nil { true } else { false } }), case let .sdJwtVc(sdJwtVc) = credential.value, let scope = sdJwtVc.scope {
			logger.info("sdJwtVc with scope \(scope), cryptographic suites: \(sdJwtVc.credentialSigningAlgValuesSupported)")
            NobidLogger.debug("issueDoc: getCredentialIdentifier: format=sdJwtVc; scope=\(scope); credentialSigningAlgValuesSupported=\(sdJwtVc.credentialSigningAlgValuesSupported); proofTypesSupported=\(sdJwtVc.proofTypesSupported); proofTypesSupported.jwt=\(sdJwtVc.proofTypesSupported?["jwt"]?.algorithms ?? [])")
            if (sdJwtVc.proofTypesSupported?["jwt"]?.algorithms.isEmpty ?? true) {
                NobidLogger.error("issueDoc: getCredentialIdentifier: proofTypesSupported.jwt IS EMPTY: See jwt/proof_types_supported in metadata: .well-known/openid-credential-issuer")
            }
			return CredentialConfiguration(configurationIdentifier: credential.key, credentialIssuerIdentifier: credentialIssuerIdentifier, docType: docType, scope: scope, display: sdJwtVc.display.map(\.displayMetadata), issuerDisplay: issuerDisplay.map(\.displayMetadata), algValuesSupported: sdJwtVc.proofTypesSupported?["jwt"]?.algorithms ?? [], msoClaims: nil, flatClaims: sdJwtVc.claims, order: nil, format: .sdjwt)
		}
		logger.error("No credential for docType \(docType ?? scope ?? identifier ?? ""). Currently supported credentials: \(credentialsSupported.keys)")
		throw WalletError(description: "Issuer does not support docType or scope or identifier \(docType ?? scope ?? identifier ?? "")")
	}

	func getCredentialIdentifiers(credentialsSupported: [CredentialConfigurationIdentifier: CredentialSupported]) throws -> [(identifier: CredentialConfigurationIdentifier, scope: String, offered: OfferedDocModel)] {
        NobidLogger.dump("VCI: processOfferRequest: getCredentialIdentifiers: credentials=\(credentialsSupported.values.map{ String(describing:$0) }.joined(separator: "-"))")

			let credentialInfos = credentialsSupported.compactMap {
				if case .msoMdoc(let msoMdocCred) = $0.value, let scope = msoMdocCred.scope, case let offered = OfferedDocModel(credentialConfigurationIdentifier: $0.key.value, docType: msoMdocCred.docType, scope: scope, displayName: msoMdocCred.display.getName(uiCulture) ?? msoMdocCred.docType, algValuesSupported: msoMdocCred.credentialSigningAlgValuesSupported) { (identifier: $0.key, scope: scope, offered: offered) }
				else if case .sdJwtVc(let sdJwtVc) = $0.value, let scope = sdJwtVc.scope, case let offered = OfferedDocModel(credentialConfigurationIdentifier: $0.key.value, docType: nil, scope: scope, displayName: sdJwtVc.display.getName(uiCulture) ?? scope, algValuesSupported: sdJwtVc.credentialSigningAlgValuesSupported) { (identifier: $0.key, scope: scope, offered: offered) }
				else {
                    nil } }
        if credentialInfos.isEmpty {
            NobidLogger.error("\nStep: VCI: processOfferRequest: getCredentialIdentifiers: Make sure that scope is not empty: offer=\(credentialsSupported.first?.value)")
        }
			return credentialInfos
	}

	private func authorizeRequestWithAuthCodeUseCase(issuer: Issuer, offer: CredentialOffer) async throws -> AuthorizeRequestOutcome {
        NobidLogger.debug("VCI: authorizeRequestWithAuthCodeUseCase: 1")
		var pushedAuthorizationRequestEndpoint = ""
		if case let .oidc(metaData) = offer.authorizationServerMetadata, let endpoint = metaData.pushedAuthorizationRequestEndpoint {
			pushedAuthorizationRequestEndpoint = endpoint
            NobidLogger.debug("VCI: authorizeRequestWithAuthCodeUseCase: 2: oidc:  pushedAuthorizationRequestEndpoint=\(pushedAuthorizationRequestEndpoint)")
		} else if case let .oauth(metaData) = offer.authorizationServerMetadata, let endpoint = metaData.pushedAuthorizationRequestEndpoint {
			pushedAuthorizationRequestEndpoint = endpoint
            NobidLogger.debug("VCI: authorizeRequestWithAuthCodeUseCase: 3: oauth:  pushedAuthorizationRequestEndpoint=\(pushedAuthorizationRequestEndpoint)")
		}
        else {
            NobidLogger.error("VCI: authorizeRequestWithAuthCodeUseCase: 4: pushedAuthorizationRequestEndpoint IS EMPTY. Search for pushedAuthorizationRequestEndpoint in metadata=\(offer.authorizationServerMetadata);")
        }
		let parPlaced = try await issuer.pushAuthorizationCodeRequest(credentialOffer: offer)

		if case let .success(request) = parPlaced, case let .par(parRequested) = request {
			self.parRequested = parRequested
            NobidLogger.success("[AUTHORIZATION] Placed PAR. Get authorization code URL is: \(parRequested.getAuthorizationCodeURL)")
			NobidLogger.taskSucceed("Authorization Request [FRONT]: Redirecting to webview: url=\(parRequested.getAuthorizationCodeURL.url)")
			let authResult = try await loginUserAndGetAuthCode(getAuthorizationCodeUrl: parRequested.getAuthorizationCodeURL.url)
			switch authResult {
			case .code(let authorizationCode):
				NobidLogger.taskSucceed("Authorization Response [FRONT]: back from webview: authorizationCode received: see dump;")
				NobidLogger.dump("Authorization Response [FRONT]: authorizationCode=\(authorizationCode)")
				return .authorized(try await handleAuthorizationCode(issuer: issuer, request: request, authorizationCode: authorizationCode))
			case .presentation_request(let url):
				NobidLogger.taskSucceed("Authorization Response [FRONT]: back from webview: presentation_request received: url=\(url)")
				return .presentation_request(url)
			}
		} else if case let .failure(failure) = parPlaced {
			NobidLogger.taskFailed("Authorization Response [FRONT]: FAILED: failure=\(failure)")
			throw WalletError(description: "Authorization error: \(failure.localizedDescription)")
		}
		NobidLogger.taskFailed("Authorization Response [FRONT]: FAILED")
		throw WalletError(description: "Failed to get push authorization code request")
	}

	private func handleAuthorizationCode(issuer: Issuer, request: UnauthorizedRequest, authorizationCode: String) async throws -> AuthorizedRequest {
		let unAuthorized = await issuer.handleAuthorizationCode(parRequested: request, authorizationCode: .authorizationCode(authorizationCode: authorizationCode))
		switch unAuthorized {
		case .success(let request):
			let authorizedRequest = await issuer.authorizeWithAuthorizationCode(authorizationCode: request)
			if case let .success(authorized) = authorizedRequest, case let .noProofRequired(token, _, _, _, _) = authorized {
				let at = token.accessToken;
				NobidLogger.taskSucceed("XXX: authorized + .noProofRequired: accessToken=\("__too_long__")")
                NobidLogger.debug("[AUTHORIZATION] Authorization code exchanged with access token : \(at)")
				return authorized
			}
            // <C> this case makes it work with current Thales server. noProofRequired is not yet supported.
            else if case let .success(authorized) = authorizedRequest { // <X> }, case let .noProofRequired(token, _, _, _) = authorized {
				NobidLogger.taskSucceed("XXX: authorized WITHOUT .noProofRequired(accessToken); authorized=\(authorized)")
                NobidLogger.error("[AUTHORIZATION] Authorization code exchanged WITHOUT access token. .noProofRequired NOT received from server as expected!!!")
                return authorized
            }
            NobidLogger.error("[AUTHORIZATION] issuer.requestAccessToken FAILED: authorizedRequest=XXX")//\(authorizedRequest)") // <ERROR> OpenId4VciService.swift:270:25 Pattern that the region based isolation checker does not understand how to check. Please file a bug

			throw WalletError(description: "Failed to get access token")
		case .failure(let error):
            NobidLogger.error("[AUTHORIZATION] issuer.requestAccessToken FAILED: error=\(error.localizedDescription)")
			throw WalletError(description: error.localizedDescription)
		}
	}

	private func noProofRequiredSubmissionUseCase(issuer: Issuer, noProofRequiredState: AuthorizedRequest, configuration: CredentialConfiguration, claimSet: ClaimSet? = nil) async throws -> IssuanceOutcome {
		switch noProofRequiredState {
		case .noProofRequired(let accessToken, let refreshToken, _, let timeStamp, _):
			let payload: IssuanceRequestPayload = .configurationBased(credentialConfigurationIdentifier: configuration.configurationIdentifier,	claimSet: claimSet)
			let responseEncryptionSpecProvider =  { @Sendable in Issuer.createResponseEncryptionSpec($0) }
            NobidLogger.debug("Step: issueDoc: noProofRequiredSubmissionUseCase: 1: ASSUMING noProof usecase: this MAY fail and then proofRequiredSubmissionUseCase will be called")
			NobidLogger.taskSucceed("ISSUANCE started with noProof assumed (this may fail with proofRequired fallback)")
			let requestOutcome = try await issuer.request(noProofRequest: noProofRequiredState, requestPayload: payload, responseEncryptionSpecProvider: responseEncryptionSpecProvider)
            NobidLogger.debug("Step: issueDoc: noProofRequiredSubmissionUseCase: 2")
            NobidLogger.dump("Step: issueDoc: noProofRequiredSubmissionUseCase: 2: requestOutcome=\(requestOutcome)")
			switch requestOutcome {
			case .success(let request):
				switch request {
				case .success(let response):
                    NobidLogger.debug("Step: issueDoc: noProofRequiredSubmissionUseCase: 3: noProof usecase is confirmed")
					if let result = response.credentialResponses.first {
						switch result {
						case .deferred(let transactionId):
							NobidLogger.taskSucceed("ISSUANCE (noProofRequired) DEFERED: transactionId=\(transactionId)")
                            NobidLogger.debug("Step: issueDoc: noProofRequiredSubmissionUseCase: 4: deferred: transactionId=\(transactionId)")
							let deferredModel = await DeferredIssuanceModel(deferredCredentialEndpoint: issuer.issuerMetadata.deferredCredentialEndpoint!, accessToken: accessToken, refreshToken: refreshToken, transactionId: transactionId, configuration: configuration, timeStamp: timeStamp)
							return .deferred(deferredModel)
						case .issued(let format, let credential, _, _):
							NobidLogger.taskSucceed("ISSUANCE (noProofRequired) ISSUED: doc.format=\(format)")
                            NobidLogger.debug("Step: issueDoc: noProofRequiredSubmissionUseCase: 5: ISSUED: format=\(format)")
							return try handleCredentialResponse(credential: credential, format: format, configuration: configuration)
						}
					} else {
                        NobidLogger.error("Step: issueDoc: noProofRequiredSubmissionUseCase: FAILED: 1")
						throw WalletError(description: "No credential response results available")
					}
				case .invalidProof(let cNonce, _):
                    NobidLogger.debug("Step: issueDoc: noProofRequiredSubmissionUseCase: 6: ASSUMING noProof usecase FAILED above so now continue with proofRequiredSubmissionUseCase")
                    NobidLogger.debug("Step: issueDoc: noProofRequiredSubmissionUseCase: 6: invalidProof: cNonce=\(cNonce)")
					NobidLogger.taskSucceed("ISSUANCE re-started with proofRequired fallback)")
					let retVal = try await proofRequiredSubmissionUseCase(issuer: issuer, authorized: noProofRequiredState.handleInvalidProof(cNonce: cNonce), configuration: configuration, claimSet: claimSet)
                    NobidLogger.debug("Step: issueDoc: noProofRequiredSubmissionUseCase: 7")
                    return retVal
				case .failed(error: let error):
					NobidLogger.taskFailed("ISSUANCE (noProofRequired) FAILED (1): error=\(error.localizedDescription)")
                    NobidLogger.error("Step: issueDoc: noProofRequiredSubmissionUseCase: FAILED: 2")
					throw WalletError(description: error.localizedDescription)
				}
			case .failure(let error):
				NobidLogger.taskFailed("ISSUANCE (noProofRequired) FAILED (2): error=\(error.localizedDescription)")
                NobidLogger.error("Step: issueDoc: noProofRequiredSubmissionUseCase: FAILED: 3")
				throw WalletError(description: error.localizedDescription)
			}
		default:
			NobidLogger.taskFailed("ISSUANCE (noProofRequired) FAILED (3): Illegal noProofRequiredState case")
			throw WalletError(description: "Illegal noProofRequiredState case")
		}
	}

	private func handleCredentialResponse(credential: Credential, format: String?, configuration: CredentialConfiguration) throws -> IssuanceOutcome {
		logger.info("Credential issued with format \(format ?? "unknown")")
		if case let .string(str) = credential  {
			// logger.info("Issued credential data:\n\(strBase64)")
			return .issued(Data(base64URLEncoded: str), str, configuration)
		} else if case let .json(json) = credential {
			return .issued(try JSONEncoder().encode(json), nil, configuration)
		} else {
			throw WalletError(description: "Invalid credential")
		}
	}

	private func proofRequiredSubmissionUseCase(issuer: Issuer, authorized: AuthorizedRequest, configuration: CredentialConfiguration?, claimSet: ClaimSet? = nil) async throws -> IssuanceOutcome {
        NobidLogger.debug("Step: issueDoc: proofRequiredSubmissionUseCase: 1: authorized=\(authorized)")
		guard case .proofRequired(let accessToken, let refreshToken, _, _, let timeStamp, _) = authorized else { throw WalletError(description: "Unexpected AuthorizedRequest case") }
        NobidLogger.debug("Step: issueDoc: proofRequiredSubmissionUseCase: 2: accessToken=\(accessToken); refreshToken=\(refreshToken)")
		guard let configuration else { throw WalletError(description: "Credential configuration not found") }
        NobidLogger.debug("Step: issueDoc: proofRequiredSubmissionUseCase: 3")
		let payload: IssuanceRequestPayload = .configurationBased(credentialConfigurationIdentifier: configuration.configurationIdentifier, claimSet: claimSet)
		let responseEncryptionSpecProvider = { @Sendable in Issuer.createResponseEncryptionSpec($0) }
        NobidLogger.debug("Step: issueDoc: proofRequiredSubmissionUseCase: 4: calling issuer.request")
		let requestOutcome = try await issuer.request(proofRequest: authorized, bindingKeys: [bindingKey], requestPayload: payload, responseEncryptionSpecProvider: responseEncryptionSpecProvider)
		switch requestOutcome {
		case .success(let request):
			switch request {
			case .success(let response):
				if let result = response.credentialResponses.first {
					switch result {
					case .deferred(let transactionId):
						NobidLogger.taskSucceed("ISSUANCE DEFERED: transactionId=\(transactionId)")
                        NobidLogger.debug("Step: issueDoc: proofRequiredSubmissionUseCase: 5: DEFERED: transactionId=\(transactionId)")
						let deferredModel = await DeferredIssuanceModel(deferredCredentialEndpoint: issuer.issuerMetadata.deferredCredentialEndpoint!, accessToken: accessToken, refreshToken: refreshToken, transactionId: transactionId, configuration: configuration, timeStamp: timeStamp)
						return .deferred(deferredModel)
					case .issued(let format, let credential, _, _):
						NobidLogger.taskSucceed("ISSUED: doc.format=\(format)")
                        NobidLogger.debug("Step: issueDoc: proofRequiredSubmissionUseCase: 6: ISSUED: format=\(format)")
						return try handleCredentialResponse(credential: credential, format: format, configuration: configuration)
					}
				} else {
					NobidLogger.taskFailed("ISSUANCE FAILED: No credential response results available")
                    NobidLogger.error("Step: issueDoc: proofRequiredSubmissionUseCase: FAILED: 1")
					throw WalletError(description: "No credential response results available")
				}
			case .invalidProof:
				NobidLogger.taskFailed("ISSUANCE FAILED: invalidProof")
                NobidLogger.error("Step: issueDoc: proofRequiredSubmissionUseCase: FAILED: 2")
				throw WalletError(description: "Although providing a proof with c_nonce the proof is still invalid")
			case .failed(let error):
				NobidLogger.taskFailed("ISSUANCE FAILED: error=\(error.localizedDescription)")
                NobidLogger.error("Step: issueDoc: proofRequiredSubmissionUseCase: FAILED: 3")
				throw WalletError(description: error.localizedDescription)
			}
		case .failure(let error):
			NobidLogger.taskFailed("ISSUANCE FAILED: error=\(error.localizedDescription)")
            NobidLogger.error("Step: issueDoc: proofRequiredSubmissionUseCase: FAILED: 4")
            throw WalletError(description: error.localizedDescription)
		}
	}

	func requestDeferredIssuance(deferredDoc: WalletStorage.Document) async throws -> IssuanceOutcome {
		let model = try JSONDecoder().decode(DeferredIssuanceModel.self, from: deferredDoc.data)
		let issuer = try getIssuerForDeferred(data: model)
		let authorized: AuthorizedRequest = .noProofRequired(accessToken: model.accessToken, refreshToken: model.refreshToken, credentialIdentifiers: nil, timeStamp: model.timeStamp, dPopNonce: nil)
		return try await deferredCredentialUseCase(issuer: issuer, authorized: authorized, transactionId: model.transactionId, configuration: model.configuration)
	}

	func resumePendingIssuance(pendingDoc: WalletStorage.Document, webUrl: URL?) async throws -> IssuanceOutcome {
		let model = try JSONDecoder().decode(PendingIssuanceModel.self, from: pendingDoc.data)
		guard case .presentation_request_url(_) = model.pendingReason else { throw WalletError(description: "Unknown pending reason: \(model.pendingReason)") }
		guard let webUrl else { throw WalletError(description: "Web URL not specified") }
		let asWeb = try await loginUserAndGetAuthCode(getAuthorizationCodeUrl: webUrl)
		guard case .code(let authorizationCode) = asWeb else { throw WalletError(description: "Pending issuance not authorized") }
		guard let offer = Self.metadataCache[model.metadataKey] else { throw WalletError(description: "Pending issuance cannot be completed") }
		let issuer = try getIssuer(offer: offer)
		logger.info("Starting issuing with identifer \(model.configuration.configurationIdentifier.value)")
		let pkceVerifier = try PKCEVerifier(codeVerifier: model.pckeCodeVerifier, codeVerifierMethod: model.pckeCodeVerifierMethod)
		let authorized = try await issuer.authorizeWithAuthorizationCode(authorizationCode: .authorizationCode(AuthorizationCodeRetrieved(credentials: [.init(value: model.configuration.configurationIdentifier.value)], authorizationCode: IssuanceAuthorization(authorizationCode: authorizationCode), pkceVerifier: pkceVerifier, configurationIds: [model.configuration.configurationIdentifier], dpopNonce: nil))).get()
		try await initSecurityKeys(algSupported: Set(model.configuration.algValuesSupported))
		let res = try await issueOfferedCredentialInternalValidated(authorized, offer: offer, issuer: issuer, configuration: model.configuration, claimSet: nil)
		Self.metadataCache.removeValue(forKey: model.metadataKey)
		return res
	}

	private func deferredCredentialUseCase(issuer: Issuer, authorized: AuthorizedRequest, transactionId: TransactionId, configuration: CredentialConfiguration) async throws -> IssuanceOutcome {
		NobidLogger.debug("[ISSUANCE] Got a deferred issuance response from server with transaction_id \(transactionId.value). Retrying issuance...")
		let deferredRequestResponse = try await issuer.requestDeferredIssuance(proofRequest: authorized, transactionId: transactionId, dPopNonce: nil)
		switch deferredRequestResponse {
		case .success(let response):
			switch response {
			case .issued(let credential):
				return try handleCredentialResponse(credential: credential, format: nil, configuration: configuration)
			case .issuancePending(let transactionId):
				logger.info("Credential not ready yet. Try after \(transactionId.interval ?? 0)")
				let deferredModel = switch authorized {
				case .noProofRequired(let accessToken, let refreshToken, _, let timeStamp, _):
					await DeferredIssuanceModel(deferredCredentialEndpoint: issuer.issuerMetadata.deferredCredentialEndpoint!, accessToken: accessToken, refreshToken: refreshToken, transactionId: transactionId, configuration: configuration, timeStamp: timeStamp)
				case .proofRequired(let accessToken, let refreshToken, _, _, let timeStamp, _):
					await DeferredIssuanceModel(deferredCredentialEndpoint: issuer.issuerMetadata.deferredCredentialEndpoint!, accessToken: accessToken, refreshToken: refreshToken, transactionId: transactionId, configuration: configuration, timeStamp: timeStamp)
				}
				return .deferred(deferredModel)
			case .errored(_, let errorDescription):
				throw WalletError(description: "\(errorDescription ?? "Something went wrong with your deferred request response")")
			}
		case .failure(let error):
			throw WalletError(description: error.localizedDescription)
		}
	}

	@MainActor
	private func loginUserAndGetAuthCode(getAuthorizationCodeUrl: URL) async throws -> AsWebOutcome {
		let lock = NSLock()
		return try await withCheckedThrowingContinuation { continuation in
			var nillableContinuation: CheckedContinuation<AsWebOutcome, Error>? = continuation
			let authenticationSession = ASWebAuthenticationSession(url: getAuthorizationCodeUrl, callbackURLScheme: config.authFlowRedirectionURI.scheme!) { url, error in
				lock.lock()
				defer { lock.unlock() }
				if let error {
					nillableContinuation?.resume(throwing: OpenId4VCIError.authRequestFailed(error))
					nillableContinuation = nil
					return
				}
				guard let url else {
					nillableContinuation?.resume(throwing: OpenId4VCIError.authorizeResponseNoUrl)
					nillableContinuation = nil
					return
				}
				if let schemes = Bundle.main.getURLSchemas(), schemes.first(where: { url.absoluteString.hasPrefix($0 + "://") }) != nil {
					// dynamic issuing case
					self.logger.info("Dynamic issuance url: \(url)")
					nillableContinuation?.resume(returning: .presentation_request(url))
					nillableContinuation = nil
				} else if let code = url.getQueryStringParameter("code") {
					self.logger.info("Dynamic issuance url: \(url)")
					nillableContinuation?.resume(returning: .code(code))
					nillableContinuation = nil
				} else {
					nillableContinuation?.resume(throwing: OpenId4VCIError.authorizeResponseNoCode)
					nillableContinuation = nil
				}
			}
			authenticationSession.presentationContextProvider = self
			authenticationSession.start()
		}
	}

	public func presentationAnchor(for session: ASWebAuthenticationSession)
	-> ASPresentationAnchor {
#if os(iOS)
		let window = UIApplication.shared.windows.first { $0.isKeyWindow }
		return window ?? ASPresentationAnchor()
#else
		return ASPresentationAnchor()
#endif
	}
}

fileprivate extension URL {
	func getQueryStringParameter(_ parameter: String) -> String? {
		guard let url = URLComponents(string: self.absoluteString) else { return nil }
		return url.queryItems?.first(where: { $0.name == parameter })?.value
	}
}

public enum OpenId4VCIError: LocalizedError {
	case authRequestFailed(Error)
	case authorizeResponseNoUrl
	case authorizeResponseNoCode
	case tokenRequestFailed(Error)
	case tokenResponseNoData
	case tokenResponseInvalidData(String)
	case dataNotValid

	public var localizedDescription: String {
		switch self {
		case .authRequestFailed(let error):
			if let wae = error as? ASWebAuthenticationSessionError, wae.code == .canceledLogin { return "The login has been canceled." }
			return "Authorization request failed: \(error.localizedDescription)"
		case .authorizeResponseNoUrl:
			return "Authorization response does not include a url"
		case .authorizeResponseNoCode:
			return "Authorization response does not include a code"
		case .tokenRequestFailed(let error):
			return "Token request failed: \(error.localizedDescription)"
		case .tokenResponseNoData:
			return "No data received as part of token response"
		case .tokenResponseInvalidData(let reason):
			return "Invalid data received as part of token response: \(reason)"
		case .dataNotValid:
			return "Issued data not valid"
		}
	}
}


