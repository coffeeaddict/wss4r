require "wss4r/aws/utils"
require "activerecordresolver"

class SimpleServiceController < ApplicationController
	
  wsdl_service_name 'SimpleService'
  web_service_scaffold :invoke
  web_service_api SimpleServiceApi
  
  #wss_add_resolvers([AuthenticateUserResolver.new()])
  #wss_add_resolvers([CertificateDirectoryResolver.new("../../certs/wse")])
  wss_add_resolvers([ActiveRecordResolver.new()])


#Encryption
  wss_add_security_tokens(
  	[EncryptedData.new(
		X509SecurityToken.new(
			security().resolver().certificate_by_subject("/C=DE/ST=Rheinland-Pfalz/L=Trier/O=FF/OU=Development/CN=Server/emailAddress=server@web.de"))),
	Signature.new(
		X509SecurityToken.new(
			security().resolver().certificate_by_subject("/C=DE/ST=Rheinland-Pfalz/L=Trier/O=FF/OU=Development/CN=Server/emailAddress=server@web.de"),
			security().resolver().private_key(security().resolver().certificate_by_subject("/C=DE/ST=Rheinland-Pfalz/L=Trier/O=FF/OU=Development/CN=Server/emailAddress=server@web.de"))
			))])

											
=begin											
#Encryption
  wss_add_security_tokens([EncryptedData.new(
									X509SecurityToken.new(
									OpenSSL::X509::Certificate.new(File.read("../../certs/ca/server.cer")))),
									Signature.new(
										X509SecurityToken.new(
											OpenSSL::X509::Certificate.new(File.read("../../certs/ca/server.cer")),
											OpenSSL::PKey::RSA.new(File.read("../../certs/ca/server.cer.key"))))])
=end

  def test(text)
	  return text.reverse
  end  
end
