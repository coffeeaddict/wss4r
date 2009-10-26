module WSS4R
module Security
module Xml

class SignatureValue
	def initialize(security_token, signed_info)
		@security_token = security_token
		@signed_info = signed_info
	end
		
	def process(document)
		canonicalizer = TransformerFactory::get_instance("http://www.w3.org/2001/10/xml-exc-c14n#")
		#esult = canonicalizer.write_document_node(@signed_info) #Broken
		result = canonicalizer.canonicalize_element(@signed_info)
		signature_value = @security_token.sign_b64(result)
		@signed_info = XPath.first(document, "//ds:SignedInfo", {"ds" => Namespaces::DS})
		signature_value_element = @signed_info.parent().add_element(Names::SIGNATURE_VALUE)
		signature_value.strip!
		signature_value_element.text=(signature_value)
		@signed_info.document()
	end
end

end #Xml
end #Security
end #WSS4R