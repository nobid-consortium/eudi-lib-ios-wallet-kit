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
import JOSESwift
import OpenID4VCI
import nobid_core

public struct OpenId4VCIConfiguration {
	public let client: Client
	public let authFlowRedirectionURI: URL
	public let authorizeIssuanceConfig: AuthorizeIssuanceConfig
	public let usePAR: Bool
	public let useDPoP: Bool  // sends headers: "DPoP: ...JWTdata" + "Authorization: DPoP ...JWTdata"
	public let useAttestationPoP: Bool	// sends headers: "OAuth-Client-Attestation: ...JWTdata" + "OAuth-Client-Attestation-PoP: ...JWTdata"

	public init(client: Client? = nil, authFlowRedirectionURI: URL? = nil, authorizeIssuanceConfig: AuthorizeIssuanceConfig = .favorScopes, usePAR: Bool = true, useDPoP: Bool = false
				, useAttestationPoP: Bool = false) {
		self.client = client ?? .public(id: "wallet-dev")
		self.authFlowRedirectionURI = authFlowRedirectionURI ?? URL(string: "eudi-openid4ci://authorize")!
		self.authorizeIssuanceConfig = authorizeIssuanceConfig
		self.usePAR = usePAR
		self.useDPoP = useDPoP
		self.useAttestationPoP = useAttestationPoP
	}
}

extension OpenId4VCIConfiguration {
	static func makedPoPConstructor(useDPoP: Bool) throws -> DPoPConstructorType? {
		NobidLogger.taskSucceed("[IPSZ][dPoP] case: useDPoP=\(useDPoP): headers: DPoP, Authorization")
		guard useDPoP else {
			NobidLogger.debug("[IPSZ][dPoP] config: dPoPConstructor NOT created: DPoP is OFF")
			return nil }
		let alg = JWSAlgorithm(.ES256)
		let privateKey = try KeyController.generateECDHPrivateKey()
		let publicKey = try KeyController.generateECDHPublicKey(from: privateKey)
		let publicKeyJWK = try ECPublicKey(publicKey: publicKey, additionalParameters: ["alg": alg.name, "use": "sig", "kid": UUID().uuidString])
		let privateKeyProxy: SigningKeyProxy = .secKey(privateKey)
		NobidLogger.debug("[IPSZ][dPoP] config: dPoPConstructor CREATED")
		return DPoPConstructor(algorithm: alg, jwk: publicKeyJWK, privateKey: privateKeyProxy)
	}

	func toOpenId4VCIConfig() -> OpenId4VCIConfig {
		NobidLogger.taskSucceed("[IPSZ][Attestation] case: useAttestationPoP=\(useAttestationPoP): headers: OAuth-Client-Attestation, OAuth-Client-Attestation-PoP")
		return OpenId4VCIConfig(client: client, authFlowRedirectionURI: authFlowRedirectionURI, authorizeIssuanceConfig: authorizeIssuanceConfig, usePAR: usePAR, dPoPConstructor: try? Self.makedPoPConstructor(useDPoP: useDPoP)
						 , clientAttestationPoPBuilder: self.useAttestationPoP == true ? DefaultClientAttestationPoPBuilder.default : nil)
	}
}
