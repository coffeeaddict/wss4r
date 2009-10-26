module WSS4R
module Security
module Xml
	
class Signature
	def initialize(security_token)
		@security_token = security_token
	end
	
	def process(document)
		security = Security.new()
		security = security.process(document)
		security_token = @security_token.process(document)
		children = security.children()
		#children.each{|child|
		#	security.delete(child)
		#}		
		security.add_element(security_token)
		signature_element = security.add_element(Names::SIGNATURE)
		#children.each{|child|
		#	security.add_element(child)
		#}
		signature_element.add_namespace("xmlns:ds", Namespaces::DS)
		signed_info = SignedInfo.new()
		signed_info_element = signed_info.process(signature_element)
		signature_value = SignatureValue.new(@security_token, signed_info_element)
		signature_value.process(document)
		key_info = KeyInfo.new(@security_token, KeyInfo::REFERENCE).get_xml(signature_element)
		document
	end

	def unprocess(signature)
		@signature_value = XPath.first(signature, "ds:SignatureValue", {"ds" => Namespaces::DS}).text().gsub("\n","")
		key_info = XPath.first(signature, "ds:KeyInfo", {"ds" => Namespaces::DS})
		@key_info = KeyInfo.new(key_info)
		@signed_info = SignedInfo.new()
		@signed_info.unprocess(signature.document())
		@signature = signature
	end
	
	def verify_signature()
		signed_info = XPath.first(@signature, "ds:SignedInfo", {"ds" => Namespaces::DS})
		inclusive_namespaces = XPath.first(signed_info, "ds:CanonicalizationMethod/InclusiveNamespaces", {"ds" => Namespaces::DS})
		prefix_list = inclusive_namespaces.attribute("PrefixList") if (inclusive_namespaces)
		if (prefix_list)
			prefix_list = prefix_list.value().split()
		end
		transformer = TransformerFactory::get_instance(@signed_info.canonicalizer_method())
		transformer.prefix_list=(prefix_list)
		result = transformer.canonicalize_element(signed_info)
		signature_value = Base64.decode64(@signature_value)#.strip()
		public_key = @key_info.security_token().certificate().public_key()
		#TODO: check certificate
		certificate = @key_info.security_token().certificate()
		
		verify = public_key.verify(OpenSSL::Digest::SHA1.new(), signature_value, result)
		raise FaultError.new(VerificationFault.new()) if !(verify)
		certitificate = @key_info.security_token().certificate()
	end

	def verify()
		@signed_info.verify()
		verify_signature()
	end
end

end #Xml
end #Security
end #WSS4R