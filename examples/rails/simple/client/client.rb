require 'soap/wsdlDriver'
require "wss4r/rpc/wssdriver"
require "wss4r/tokenresolver/certificateresolver"
require "wss4r/tokenresolver/authenticateuserresolver"

include SOAP::RPC
include WSS4R::Tokenresolver

def encrypt(driver)
	resolver = CertificateDirectoryResolver.new("../../../certs/ca")
	driver.security().add_security_resolver(resolver)
	x509 = X509SecurityToken.new(Certificate.new(File.read("../../../certs/ca/client.cer")))
	driver.security().add_security_token(EncryptedData.new(x509))
end

def username(driver)
	user = "Roland"
	resolver = CertificateDirectoryResolver.new("../../../certs/ca")
	driver.security().add_security_resolver(resolver)
	resolver = AuthenticateUserResolver.new()
	driver.security().add_security_resolver(resolver)
	driver.security().add_security_token(UsernameToken.new(user, user.reverse()))
end

def sign(driver)
	resolver = CertificateDirectoryResolver.new("../../../certs/ca")
	driver.security().clear_resolver!()
	driver.security().add_security_resolver(resolver)
	sign_cert = resolver.certificate_by_subject("/C=DE/ST=Rheinland-Pfalz/L=Trier/O=FF/OU=Development/CN=Server/emailAddress=server@web.de")
	pkey = resolver.private_key(sign_cert)
	x509 = X509SecurityToken.new(sign_cert, pkey)
	signature = Signature.new(x509)
	driver.security().add_security_token(signature)
end

WSDL_URL = "http://localhost:3000/simple_service/service.wsdl"

soapDriver = SOAP::WSDLDriverFactory.new(WSDL_URL).create_rpc_driver()

sign(soapDriver)
#username(soapDriver)
#encrypt(soapDriver)

puts "============================================="
puts(soapDriver.test("test"))
puts "============================================="


