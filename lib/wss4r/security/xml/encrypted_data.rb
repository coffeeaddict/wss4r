module WSS4R
  module Security
    module Xml

      class EncryptedData
        attr_accessor :cipher_value, :ref_id, :algorithm, :sessionkey_algorithm, :security_token
	
        def initialize(security_token=nil)
          if (security_token != nil)
            @security_token = security_token
          end
          @sessionkey_algorithm = Types::ALGORITHM_3DES_CBC
        end
   
        def unprocess(encrypted_data)
          cipher_value = XPath.first(encrypted_data, "xenc:CipherData/xenc:CipherValue", {"xenc" => Namespaces::XENC})
          algorithm = XPath.first(encrypted_data, "xenc:EncryptionMethod", {"xenc" => Namespaces::XENC})
          ref_id = encrypted_data.attributes["Id"]
          self.cipher_value=(cipher_value.text())
          self.ref_id=(ref_id)
          self.algorithm=(algorithm.attributes["Algorithm"])
        end
   
        def process(document)
          root = document.root()
          soap_ns = nil
          soap_prefix = root.prefix()
          root.attributes.each_attribute() {|attr|
            if (attr.value() == Namespaces::S11)
              soap_ns = Namespaces::S11
            end
            if (attr.value() == Namespaces::S12)
              soap_ns = Namespaces::S12
            end
          }
          old_soap_body = XPath.first(document, "/env:Envelope/env:Body", {SOAPParser::soap_prefix=>SOAPParser::soap_ns})
          #old_soap_body = SOAPParser.part(SOAPParser::BODY)

          soap_body_string = ""
          if defined?(REXML::Formatters)
            formatter = REXML::Formatters::Default.new
            old_soap_body.each_element(){|e|            
              formatter.write(e, soap_body_string)
            }
          else
            old_soap_body.each_element(){|e|            
              e.write(soap_body_string)
            }
          end                        
          root.delete(old_soap_body)
          soap_body = root.add_element(Names::BODY)
          old_soap_body.attributes().each_attribute{|a|
            soap_body.add_attribute(a.expanded_name(), a.value())
            #puts(a.expanded_name() + " => " + a.value())
          }
          digest = CryptHash.new().digest_b64(soap_body.to_s()).strip()
          encrypted_data = soap_body.add_element(Names::ENCRYPTED_DATA)
          encrypted_data.add_namespace("xmlns:xenc", Namespaces::XENC)
          @ref_id = "EncryptedContent-"+digest.to_s()
          encrypted_data.add_attributes({"Type"=>Types::XENC_CONTENT, "Id"=>@ref_id})

          if (@sessionkey_algorithm == Types::ALGORITHM_3DES_CBC)
            symmetric_encrypter = TripleDESSymmetricEncrypter.new()
          elsif (@sessionkey_algorithm == Types::ALGORITHM_AES_CBC)
            symmetric_encrypter = AESSymmetricEncrypter.new()
          elsif (@sessionkey_algorithm == Types::ALGORITHM_AES128_CBC)
            symmetric_encrypter = AES128SymmetricEncrypter.new()            
          else
            raise "Unsupported encryption algorithm #{@sessionkey_algorithm}"
          end
          encryption_method = encrypted_data.add_element(Names::ENCRYPTION_METHOD)
          encryption_method.add_attribute("Algorithm", @sessionkey_algorithm)
          encrypted_body = symmetric_encrypter.encrypt_to_b64(symmetric_encrypter.iv() + soap_body_string)
          encrypted_key = EncryptedKey.new(@security_token, symmetric_encrypter, self)
          cipher_data = encrypted_data.add_element(Names::CIPHER_DATA)
          cipher_value = cipher_data.add_element(Names::CIPHER_VALUE)
          cipher_value.text=(encrypted_body.gsub("\n",""))
          encrypted_key.process(document)      
        end
   
        def decrypt(document, encrypted_key)
          if (algorithm == Types::ALGORITHM_3DES_CBC) 
            symmetric_encrypter = TripleDESSymmetricEncrypter.new(encrypted_key.symmetric_key())
          elsif (algorithm == Types::ALGORITHM_AES_CBC)
            symmetric_encrypter = AESSymmetricEncrypter.new(encrypted_key.symmetric_key())
          elsif (algorithm == Types::ALGORITHM_AES128_CBC)
            symmetric_encrypter = AES128SymmetricEncrypter.new(encrypted_key.symmetric_key())
          else
            raise "Unsupported encryption algorithm #{algorithm}"
          end
          raw_data = Base64.decode64(@cipher_value)
          symmetric_encrypter.iv=(raw_data)
          decrypted_element = symmetric_encrypter.decrypt(raw_data)
          reference = encrypted_key.reference_list().uris()[0]		
          reference = reference[1..-1] # remove leading #
          encrypted_element = XPath.first(document, "//*[@Id='"+reference+"']")
          parent = encrypted_element.parent()
		
          #document.root().delete_element("//" + Names::SECURITY)
          parent.delete(encrypted_element)
		
          new_element = Document.new(decrypted_element)
          parent.add(new_element)
          #puts("encrypted_data.decrypt: " + element.to_s())
        end
      end

    end #Xml
  end #Security
end #WSS4R
