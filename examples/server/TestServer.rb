require "wss4r/server/wssstandaloneserver"
require "wss4r/security/security"
require "wss4r/tokenresolver/certificateresolver"
require "wss4r/tokenresolver/authenticateuserresolver"

include WSS4R::Server
include WSS4R::Tokenresolver

class TestServer < WSSStandaloneServer
  SIGN = "SIGN"
  ENC = "ENC"
  USERNAME = "USER"
  SUBJECT_SERVER = "/C=DE/ST=Rheinland-Pfalz/L=Trier/O=FF/OU=Development/CN=Server/emailAddress=server@web.de"
  SUBJECT_CLIENT = "/C=DE/ST=Rheinland-Pfalz/L=Trier/O=FF/OU=Developement/CN=Client/emailAddress=client@web.de"

  def on_init()
    STDOUT.sync = true
    add_method(self, "multiply", "a", "b")
    add_method(self, "SayHello", "to")
    username() if (ARGV[0].upcase() == USERNAME)
    encrypt() if (ARGV[0].upcase() == ENC)
    sign() if (ARGV[0].upcase() == SIGN)
    if (ARGV.size() == 2)
      encrypt() if (ARGV[1].upcase() == ENC)
      sign() if (ARGV[1].upcase() == SIGN)
    end
  end
  
  def sign()
    @resolver = CertificateDirectoryResolver.new("../certs/ca/")
    security().clear_resolver!()
    security().add_security_resolver(@resolver)

    sign_cert = @resolver.certificate_by_subject(SUBJECT_SERVER)
    pkey = @resolver.private_key(sign_cert)
    x509 = X509SecurityToken.new(sign_cert, pkey)
    signature = Signature.new(x509)
    security().add_security_token(signature)
  end
	
  def encrypt()
    @resolver = CertificateDirectoryResolver.new("../certs/ca/")
    security().clear_resolver!()
    security().add_security_resolver(@resolver)

    cert = @resolver.certificate_by_subject(SUBJECT_CLIENT)
    x509 = X509SecurityToken.new(cert)
    enc_data = EncryptedData.new(x509)
    enc_data.sessionkey_algorithm = Types::ALGORITHM_AES128_CBC
    security().add_security_token(enc_data)
  end
	
  def username()
    userresolver = AuthenticateUserResolver.new()
    security().clear_tokens!()
    security().clear_resolver!()
    security().add_security_resolver(userresolver)
  end
        
  def SayHello(name)
    return "Hello, " + name
  end
	
  def multiply(a,b)
    begin
      return (a*b)
    rescue
      SOAPFault.new(SOAPString.new("User not authenticated!"), SOAPString.new("error"), SOAPString.new(self.class.name))
    end
  end
end

if $0 == __FILE__
  server = TestServer.new("multiply", "urn:multiply", "127.0.0.1", 8080)
  server.start()
  trap(:INT) do 
    server.shutdown
  end
end
