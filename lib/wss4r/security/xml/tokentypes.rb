module WSS4R
  module Security
    module Xml

      class SecurityToken
        def add_namespace(document, prefix, ns)
          document.root().add_namespace("xmlns:"+prefix, ns)
        end
      end

      class BinarySecurityToken < SecurityToken
      end

      class X509SecurityToken < BinarySecurityToken
        attr_reader :certificate
        attr_accessor :private_key
	
        def initialize(x509certificate, private_key = nil)
          if (x509certificate.kind_of?(Certificate))
            @certificate = x509certificate
          elsif x509certificate.instance_of?(String)
            @certificate = Certificate.new(Base64.decode64(x509certificate))
          end
          @private_key = private_key
        end
   
        def process(document)
          e = Element.new(Names::BINARY_SECURITY_TOKEN)
          e.add_namespace("xmlns:wsu", Namespaces::WSU)
          der_certificate_string = Base64.encode64(@certificate.to_der())
          der_certificate_string.delete!("\n\r")

          e.add_text(der_certificate_string)
          e.add_attribute("wsu:Id", get_id())
		
          e.add_attribute("ValueType", Types::REFERENCE_VALUETYPE_X509)
          e.add_attribute("EncodingType", Types::ENCODING_X509V3)
          return e
        end
   
        def get_id()
          unless @id
            @id = Crypto::CryptHash.new().digest_b64(@certificate.public_key().to_s()+Time.new().to_s()).to_s().strip()
          end
          @id
        end

        def key_identifier()
          if (@key_identifier == nil)
            ext = @certificate.extensions()[2]
            return (Base64.encode64(ext.to_der()[11..30]))
          else
            return @key_identifier
          end
        end

        def key_identifier=(id)
          @key_identifier = id
        end
	
        def public_encrypt_b64(text)
          ciphervalue = @certificate.public_key().public_encrypt(text)
          return Base64.encode64(ciphervalue)
        end
   
        def private_decrypt_b64(text)
          @private_key.private_decrypt(Base64.decode64(text.strip()))
        end
   
        def serial_number()
          @certificate.serial()
        end
   
        def get_issuer_name()
          @certificate.issuer()
        end
   
        def sign_b64(to_sign)
          plain_signature = @private_key.sign(OpenSSL::Digest::SHA1.new(), to_sign)
          signature = Base64.encode64(plain_signature)
          signature.strip!
          signature
        end
	
        def public_key()
          return @certificate.public_key()
        end
      end

      class UsernameToken < SecurityToken
        PLAIN = "PLAIN"
        HASHED = "HASHED"
        attr_accessor :username, :password, :type, :nonce, :created, :hash, :type
	
        def initialize(username = nil, password = nil, type = HASHED)
          @username = username
          @password = password
          @type = type
        end
	
        def unprocess(usernametoken)
          @username = XPath.first(usernametoken, "wsse:Username", {"wsse"=>Namespaces::WSSE}).text()
          @password = XPath.first(usernametoken, "wsse:Password", {"wsse"=>Namespaces::WSSE}).text()
          password_type = XPath.first(usernametoken, "wsse:Password", {"wsse"=>Namespaces::WSSE}).attribute("Type").value()
          if password_type == Types::PASSWORD_DIGEST
            @type = HASHED
            @nonce    = XPath.first(usernametoken, "wsse:Nonce", {"wsse"=>Namespaces::WSSE}).text()
            @created  = XPath.first(usernametoken, "wsu:Created", {"wsu"=>Namespaces::WSU}).text()
          else 
            @type = PLAIN
          end
          @hash = @password
        end
	
        def process(document)
          wsse_security = XPath.first(document, "/env:Envelope/env:Header/wsse:Security")
          username_token = wsse_security.add_element("wsse:UsernameToken")
          username_token.add_namespace("xmlns:wsu", Namespaces::WSU)
          username_token.add_attribute("wsu:Id", "SecurityToken-" + username_token.object_id().to_s())
          username = username_token.add_element("wsse:Username")
          username.text=(@username)

          if @password.nil?
            # no password provided
          elsif @type == HASHED
            password = username_token.add_element("wsse:Password")
            #BUG #4400
            #password.add_attribute("Type", Types::PASSWORD_DIGEST)
            #Solution--------------------------------------------------
            created = username_token.add_element("wsu:Created")
            created_time = Time.new.getutc()
            #created_time = (Time.new()-(60*60*1)).getutc.iso8601()	
            #----------------------------------------------------------
            created.text=(created_time)

            password.add_attribute("Type", Types::PASSWORD_DIGEST)
            nonce = username_token.add_element("wsse:Nonce")
            nonce_text = OpenSSL::Random.random_bytes(20).to_s().strip()
            nonce.text=(Base64.encode64(nonce_text))
            stamp = nonce_text.to_s() + created_time.to_s() + @password.to_s()
            hash = CryptHash.new().digest_b64(stamp)
            password.text=(hash.to_s())
          else
            password = username_token.add_element("wsse:Password")
            password.add_attribute("Type", Types::PASSWORD_TEXT)
            password.text=@password
          end
		
          # BUG #5877 -----------------------------------------------
          #created_time = (Time.new()-(60*60*1)).iso8601()
          #created_time = created_time[0..created_time.index("+")]
          #created_time[-1]="Z"
          #----------------------------------------------------------
		
        end
      end

    end #Xml
  end #Security
end #WSS4R


if __FILE__ == $0
  require "rexml/document"
  require "pp"
  require "wss4r/rpc/wssdriver"
  include REXML
  document = Document.new(File.new(ARGV[1]))
  if ARGV[0] == "p"
    usernametoken = WSS4R::Security::Xml::UsernameToken.new("Ron","noR")
    usernametoken.process(document)
    pp(document.to_s())
  else
    element = XPath.match(document, "/soap:Envelope/soap:Header/wsse:Security/wsse:UsernameToken")[0]
    usernametoken = WSS4R::Security::Xml::UsernameToken.new()
    usernametoken.unprocess(element)
  end
end
	
	
