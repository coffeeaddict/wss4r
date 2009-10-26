require "wss4r/rpc/wssdriver"
require "wss4r/tokenresolver/certificateresolver"
require "wss4r/tokenresolver/authenticateuserresolver"

include SOAP::RPC
include WSS4R::Tokenresolver

class Test
  SIGN = "SIGN"
  ENC = "ENC"
  USERNAME_HASH = "USER_HASH"
  USERNAME_PLAIN = "USER_PLAIN"
  SUBJECT_SERVER = "/C=DE/ST=Rheinland-Pfalz/L=Trier/O=FF/OU=Development/CN=Server/emailAddress=server@web.de"
  SUBJECT_CLIENT = "/C=DE/ST=Rheinland-Pfalz/L=Trier/O=FF/OU=Developement/CN=Client/emailAddress=client@web.de"
	
  def initialize(mode)
    @driver = Driver.new('http://localhost:8080/','urn:multiply')
    @driver.add_method('multiply','a','b')
    username(USERNAME_HASH) if (mode[0].upcase() == USERNAME_HASH)
    username(USERNAME_PLAIN) if (mode[0].upcase() == USERNAME_PLAIN)
    encrypt() if (mode[0].upcase() == ENC)
    sign() if (mode[0].upcase() == SIGN)
    if (ARGV.size() == 2)
      encrypt() if (mode[1].upcase() == ENC)
      sign() if (mode[1].upcase() == SIGN)
    end
		
    puts("Ergebnis: " + @driver.multiply(10,30).to_s())
  end
	
  def username(type)
    userresolver = AuthenticateUserResolver.new()
    @driver.security().clear_tokens!()
    @driver.security().clear_resolver!()
    @driver.security().add_security_resolver(userresolver)
    if type == USERNAME_HASH
      usernametoken = UsernameToken.new("Ron", "noR", UsernameToken::HASHED)
    else
      usernametoken = UsernameToken.new("Ron", "noR", UsernameToken::PLAIN)	
    end
    @driver.security().add_security_token(usernametoken)		
  end
	
  def encrypt()
    @resolver = CertificateDirectoryResolver.new("../certs/ca")
    @driver.security().clear_resolver!()
    @driver.security().add_security_resolver(@resolver)
    cert = @resolver.certificate_by_subject(SUBJECT_SERVER)
    x509 = X509SecurityToken.new(cert)
    enc_data = EncryptedData.new(x509)
    enc_data.sessionkey_algorithm = Types::ALGORITHM_AES128_CBC
    @driver.security().add_security_token(enc_data)
  end

  def sign
    @resolver = CertificateDirectoryResolver.new("../certs/ca")
    @driver.security().clear_resolver!()
    @driver.security().add_security_resolver(@resolver)
    sign_cert = @resolver.certificate_by_subject(SUBJECT_SERVER)
    pkey = @resolver.private_key(sign_cert)
    x509 = X509SecurityToken.new(sign_cert, pkey)
    signature = Signature.new(x509)
    @driver.security().add_security_token(signature)
  end
end

Test.new(ARGV)
