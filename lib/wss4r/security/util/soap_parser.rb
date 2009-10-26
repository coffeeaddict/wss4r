module WSS4R
module Security
module Util

class SOAPParser
	BODY = "/env:Envelope/env:Body"
	ENVELOPE = "/env:Envelope"
	HEADER = "/env:Envelope/env:Header"
	
	KEY_IDENTIFIER = "//wsse:SecurityTokenReference//wsse:KeyIdentifier"
	SECURITY = "/env:Envelope/env:Header/wsse:Security"
	CIPHER_DATA = "//xenc:CipherData//xenc:CipherValue"
	CIPHER_VALUE = "//xenc:CipherValue"
	SIGNED_INFO = "//ds:SignedInfo"
	ENCRYPTION_METHOD = "//xenc:EncryptionMethod"
	KEY_INFO = "//ds:KeyInfo"
	REFERENCE_LIST = "//env:Envelope/env:Header/wsse:Security/xenc:EncryptedKey/xenc:ReferenceList"
	SIGNATURE = "/env:Envelope/env:Header/wsse:Security/ds:Signature"
	ENCRYPTED_KEY = "/env:Envelope/env:Header/wsse:Security/xenc:EncryptedKey"
	@@document = nil
	@@prefix = nil
	@@soap_ns = nil
	@@soap_prefix = nil
	
	def self.document()
		@@document
	end
	
	def self.document=(value) 
		@@document = value
		prefix = @@document.root().prefix() #set the prefix to env or soap
		BODY.gsub!("env:", prefix+":")
		ENVELOPE.gsub!("env:", prefix+":")
		HEADER.gsub!("env:", prefix+":")
		SECURITY.gsub!("env:", prefix+":")
		REFERENCE_LIST.gsub!("env:", prefix+":")
		SIGNATURE.gsub!("env:", prefix+":")
		ENCRYPTED_KEY.gsub!("env:", prefix+":")
	end 

	def self.soap_ns=(ns)
		@@soap_ns = ns
	end
	def self.soap_prefix=(prefix)
		@@soap_prefix = prefix
	end
	def self.soap_ns()
		@@soap_ns
	end
	def self.soap_prefix()
		@@soap_prefix
	end
	def self.part(type)
		element = @@document.select(type)
		element
	end

	def self.element(element, type)
		result = @@document.select_element(element, type)
		result
	end
end

end #Util
end #Security
end #WSS4R

if __FILE__ == $0
	document = REXML::Document.new(File.new(ARGV[0]))
	WSS4R::Security::Util::SOAPParser.document=(document)
	result = WSS4R::Security::Util::SOAPParser.part(WSS4R::Security::Util::SOAPParser::ENVELOPE)
	puts(result)
end