require "wss4r/rpc/wssdriver"
require "wss4r/tokenresolver/certificateresolver"

include SOAP::RPC
include WSS4R::Tokenresolver

class Test
	SIGN = "sign"
	ENC = "enc"
	USER = "user"
	
   def initialize(mode)
      @driver = Driver.new('http://localhost:8080/securesimple/Ping',"http://xmlsoap.org/Ping")
      @driver.default_encodingstyle = SOAP::EncodingStyle::ASPDotNetHandler::Namespace
		@driver.add_method('Ping', 'ticket','text')
		@driver.generate_explicit_type=false

		resolver = CertificateDirectoryResolver.new("../certs/jwsdp_16")
		@driver.security().add_security_resolver(resolver)

		encrypt() if (mode[0] == ENC)
		sign() if (mode[0] == SIGN)
		encrypt() if (mode[1] == ENC)
		sign() if (mode[1] == SIGN)		
		username() if (mode[0] == USER)	
      puts("Ergebnis: ", @driver.Ping("SUNW","Toller Test!"))
	end
	
	def encrypt()
		encrypt_cert = OpenSSL::X509::Certificate.new(File.read("../certs/jwsdp_16/server.cer"))
		x509 = X509SecurityToken.new(encrypt_cert)
		enc_data = EncryptedData.new(x509)
		enc_data.sessionkey_algorithm=(Types::ALGORITHM_3DES_CBC)
		@driver.security().add_security_token(enc_data)		
	end

	def sign()
		sign_cert = OpenSSL::X509::Certificate.new(File.read("../certs/jwsdp_16/client.cer"))
		pkey = OpenSSL::PKey::RSA.new(File.read("../certs/jwsdp_16/client.cer.key"))
		x509 = X509SecurityToken.new(sign_cert,pkey)
		signature = Signature.new(x509)
		@driver.security().add_security_token(signature)					
	end
	
	def username()
		usernametoken = UsernameToken.new("Ron", "noR")
		@driver.security().add_security_token(usernametoken)		
	end
end

Test.new(ARGV)