module WSS4R
module Security
module Util

class TransformerFactory 
	def TransformerFactory::get_instance(type)
		case type
			when "http://www.w3.org/2001/10/xml-exc-c14n#"
				return XmlCanonicalizer.new(false,true)
			else
				return XmlCanonicalizer.new(false,true)
		end
	end
end

class DigestFactory
	def DigestFactory::get_instance(type)
		case type
			when "http://www.w3.org/2000/09/xmldsig#sha1"
				return CryptHash.new() #OpenSSL::Digest::SHA1.new()
			else
				return CryptHash.new() #OpenSSL::Digest::SHA1.new()
		end
	end
end

end #WSS4R
end #Security
end #Util
