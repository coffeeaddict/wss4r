module WSS4R
module Security
module Xml
	
class KeyInfo
	attr_accessor :security_token, :type, :key_identifier

	KEY_IDENTIFIER = "KEY_IDENTIFIER"
	REFERENCE = "REFERENCE"

	def initialize(p, *type)
		if (p.kind_of?(SecurityToken))
			@security_token = p                                 
			if (type != nil)
				@type = type 
			else
				@type = KEY_IDENTIFIER
			end
		else
			reference = XPath.first(p, "wsse:SecurityTokenReference/wsse:Reference", {"wsse" => Namespaces::WSSE})
			@uri = reference.attribute("URI").value()[1..-1]
			@value_type = reference.attribute("ValueType").value()
			@ref_element = XPath.first(p.document(), "//*[@wsu:Id='"+@uri+"']")
			@security_token = X509SecurityToken.new(@ref_element.text())
		end
	end
	
	def get_xml(parent)
		key_info = parent.add_element(Names::KEY_INFO)
		security_token_ref = key_info.add_element(Names::SECURITY_TOKEN_REFERENCE)
		security_token_ref.add_namespace("xmlns:wsu", Namespaces::WSU)
		wsu_id = REXML::Attribute.new("wsu:Id",security_token_ref.object_id().to_s())
		security_token_ref.add_attribute(wsu_id)
		if (@type == "KEY_IDENTIFIER")
			key_identifier = security_token_ref.add_element(Names::KEY_IDENTIFIER)
			key_identifier.add_attribute("ValueType", Types::VALUE_KEYIDENTIFIER)
			key_identifier.add_attribute("EncodingType", Types::ENCODING_X509V3)
			key_identifier.text=(@security_token.key_identifier())
		else
			reference = security_token_ref.add_element(Names::REFERENCE_WSSE)
			reference.add_attribute("ValueType", Types::REFERENCE_VALUETYPE_X509)
			reference.add_attribute("URI", "#"+@security_token.get_id())
		end
		parent
	end

	
end

end #Xml
end #Security
end #WSS4R