module WSS4R
  module Security
    module Xml

      class Security
	def initialize()
	end
	
	def process(document)
          security = XPath.first(document, "/env:Envelope/env:Header/wsse:Security")#, {SOAPParser::soap_prefix=>SOAPParser::soap_ns})
          return security if (security != nil)
          header = XPath.first(document, "/env:Envelope/env:Header", {SOAPParser::soap_prefix=>SOAPParser::soap_ns})
          security = header.add_element(Names::SECURITY, {"env:mustUnderstand"=>"1"})
          security.add_namespace("xmlns:wsse", Namespaces::WSSE)
          Timestamp.new().process(security)
          security
	end

	def unprocess(document)
          # Is the document signed?
          #signature_element = SOAPParser.part(SOAPParser::SIGNATURE)
          #wsse = XPath.first(document, "/soap:Envelope/soap:Header/wsse:Security", {"soap"=>Namespaces::SOAP})
          wsse = XPath.first(document, "/env:Envelope/env:Header/wsse:Security")
		
          timestamp = XPath.first(document, "/soap:Envelope/soap:Header/wsse:Security/wsu:Timestamp", {"soap"=>Namespaces::SOAP, "wsse"=>Namespaces::WSSE, "wsu"=>Namespaces::WSU})
          #TODO: check timestamp, if it exists
          if (timestamp != nil)
            t = Timestamp.new()
            t.unprocess(timestamp)
            t.verify()
          end
          signature_element = XPath.first(document, "/env:Envelope/env:Header/wsse:Security/ds:Signature", {"env"=>Namespaces::SOAP, "ds"=>Namespaces::DS})
          header = XPath.first(document, "/env:Envelope/env:Header", {"env"=>Namespaces::SOAP, "ds"=>Namespaces::DS})
		
          encrypted_key_element = SOAPParser.part(SOAPParser::ENCRYPTED_KEY)

          signature_index = wsse.index_of(signature_element) || 0
          encryption_index = wsse.index_of(encrypted_key_element)
            
          if (signature_index < encryption_index) 
            if (signature_element != nil)	
              handle_signature(signature_element)
            end
            encrypted_key_element = SOAPParser.part(SOAPParser::ENCRYPTED_KEY)
            if (encrypted_key_element != nil)
              handle_encryption(document, encrypted_key_element)
            end
          else
            encrypted_key_element = SOAPParser.part(SOAPParser::ENCRYPTED_KEY)
            if (encrypted_key_element != nil)
              handle_encryption(document, encrypted_key_element)
            end
            signature_element = XPath.first(document, "/env:Envelope/env:Header/wsse:Security/ds:Signature", {"env"=>Namespaces::SOAP, "ds"=>Namespaces::DS})
            if (signature_element != nil)	
              handle_signature(signature_element)
            end
          end	            
          #UsernameToken in the document?
          usernametoken = XPath.first(document, "/env:Envelope/env:Header/wsse:Security/wsse:UsernameToken", {"env"=>Namespaces::SOAP, "ds"=>Namespaces::DS})
          if (usernametoken)
            handle_usernametoken(document, usernametoken)
          end	
	end
	
	def handle_signature(signature_element)
          signature = Signature.new(nil)
          signature.unprocess(signature_element)
          signature.verify()
	end
	
	def handle_encryption(document, encrypted_key_element)
          encrypted_key = EncryptedKey.new()
          encrypted_key.unprocess(encrypted_key_element)
          encrypted_data = EncryptedData.new(encrypted_key.x509security_token())
          body = SOAPParser.part(SOAPParser::BODY)
          encrypted_data.unprocess(body.get_elements("//xenc:EncryptedData")[0])
          encrypted_data.decrypt(document, encrypted_key)
	end
	
	def handle_usernametoken(document, token)          
          usernametoken = UsernameToken.new()
          usernametoken.unprocess(token)
          resolver = WSS4R::Security::Security.new().resolver()
          success = resolver.authenticate_user(usernametoken)
          return true if success
          raise Exception.new("User not authenticated!") if (!success)
	end
      end

    end #Xml
  end #Security
end #WSS4R