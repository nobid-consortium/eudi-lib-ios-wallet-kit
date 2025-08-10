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
public extension DocElements {
	var isPaymentMSCT: Bool {
		//	name=BANCOMAT
		//	docType=A2PayIntesa
		docTypeOrVct == "A2PayIntesa"
	}
	var isPaymentOther: Bool {
		//	name=Nobid SEPA Inst (nobid-backend.digitallabor.dev)
		//	docType=urn:eu.europa.nobid:a2pay:1
		docTypeOrVct == "urn:eu.europa.nobid:a2pay:1"
	}
}

public extension Array where Element == DocElements {
  func filterPaymentDocuments() -> [DocElements] {
	  self.filter { $0.isPaymentMSCT || $0.isPaymentOther }
  }
}
