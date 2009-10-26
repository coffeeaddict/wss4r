module WSS4R
module Security
module Xml

class EncryptedKey
	attr_reader :x509security_token, :symmetric_encrypter, :symmetric_key, :reference_list
	
   def initialize(x509security_token=nil, symmetric_encrypter=nil, encrypted_data = nil)
      @x509security_token = x509security_token
      @symmetric_encrypter = symmetric_encrypter
      @encrypted_data = encrypted_data
      @reference_list = nil
   end
   
   def unprocess(encrypted_key)
		#key_info = SOAPParser.element(encrypted_key, SOAPParser::KEY_INFO)
		algorithm = XPath.first(encrypted_key, "//xenc:EncryptionMethod", {"xenc" => Namespaces::XENC})
		key_info_element = XPath.first(encrypted_key, "ds:KeyInfo", {"ds"=>Namespaces::DS})
		key_info = KeyInfo.new(key_info_element)
      resolver = WSS4R::Security::Security.new().resolver()
      @reference_list = ReferenceList.new(encrypted_key.get_elements("//xenc:ReferenceList")[0])
		private_key = resolver.private_key(key_info.security_token().certificate())
		key_info.security_token().private_key=(private_key)
		
      @x509security_token = key_info.security_token()
		
		cipher_value = XPath.first(encrypted_key, "xenc:CipherData/xenc:CipherValue", {"xenc" => Namespaces::XENC})
      @symmetric_key = @x509security_token.private_decrypt_b64(cipher_value.text())
   end   
   
   def process(document)
      #Encrypts the symmetric key with the public key from the certificate and add an EncryptedKey element to env:Body/wsse:Security
		#@x509security_token.get_xml(document)
		wsse_security = Security.new()
		wsse_security = wsse_security.process(document)
		security_token = @x509security_token.process(document)

		children = wsse_security.children()
		children.each{|child|
			wsse_security.delete(child)
		}		
		wsse_security.add_element(security_token)
		encrypted_key = wsse_security.add_element(Names::ENCRYPTED_KEY)
		children.each{|child|
			wsse_security.add_element(child)
		}
      
      encrypted_key.add_namespace("xmlns:xenc", Namespaces::XENC)
      document.add_namespace("xmlns:xenc", Namespaces::XENC)
      encryption_method = encrypted_key.add_element(Names::ENCRYPTION_METHOD)
      encryption_method.add_attribute("Algorithm", Types::ALGORITHM_RSA15)
      key_info = encrypted_key.add_element(Names::KEY_INFO)
		key_info.add_namespace("xmlns:ds",Namespaces::DS)
      security_token_ref = key_info.add_element(Names::SECURITY_TOKEN_REFERENCE)
		reference = security_token_ref.add_element("wsse:Reference")
		
		reference.add_attribute("URI", "#"+@x509security_token.get_id())
		reference.add_attribute("ValueType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3")
      cipher_data = encrypted_key.add_element(Names::CIPHER_DATA)
      cipher_value = cipher_data.add_element(Names::CIPHER_VALUE)
      cipher_value.text = @x509security_token.public_encrypt_b64(@symmetric_encrypter.key()).gsub("\n","")
      reference_list = encrypted_key.add_element(Names::REFERENCE_LIST)
      data_reference = reference_list.add_element(Names::DATA_REFERENCE)
		data_reference.add_attribute("URI", "#" + @encrypted_data.ref_id())
   end   
   
   def symmetric_encrypter()
      @symmetric_encrypter
   end
end

end #Xml
end #Security
end #WSS4R
