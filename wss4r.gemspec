WSS4R_FILES = %w{
  wss4r.gemspec
  lib/wss4r/aws/utils.rb
  CHANGELOG
  README
  gpl
  rubys
  copying
  lib/config/config.rb
  lib/rpc/proxy.rb
  lib/rpc/router.rb
  lib/rpc/wssdriver.rb
  lib/security/crypto/certificate.rb
  lib/security/crypto/cipher.rb
  lib/security/crypto/hash.rb
  lib/security/exceptions/exception.rb
  lib/security/resolver.rb
  lib/security/security.rb 
  lib/security/util/hash_util.rb
  lib/security/util/names.rb
  lib/security/util/namespaces.rb
  lib/security/util/soap_parser.rb
  lib/security/util/transformer_factor.rb
  lib/security/util/types.rb
  lib/security/util/xmlcanconicalizer.rb
  lib/security/util/xmlutils.rb
  lib/security/xml/encrypted_data.rb
  lib/security/xml/encrypted_key.rb
  lib/security/xml/key_info.rb
  lib/security/xml/reference.rb
  lib/security/xml/reference_list.rb
  lib/security/xml/security.rb
  lib/security/xml/signature.rb
  lib/security/xml/signature_value.rb
  lib/security/xml/signed_info.rb
  lib/security/xml/timestamp.rb
  lib/security/xml/tokentypes.rb
  lib/server/wssstandaloneserver.rb
  lib/soap/processor.rb
  lib/tokenresolver/authenticateuserresolver.rb
  lib/tokenresolver/certificateresolver.rb
  lib/tokenresolver/databaseresolver.rb
  lib/tokenresolver/resolver.rb
  util/create_x509cert.rb
  util/DumpPrivateKey.class
  util/encrypt_xml.rb
  util/hints.txt
  util/xmlsec-verify.bat
  xml/out.xml
  xml/wse-encrypted-signed.xml
  xml/wse-signed.xml
  xml/wse-usernametoken-sign.xml
  xml/wse-usernametoken.xml
  xml/wss4r-encrypted-signed.xml
  xml/wss4r-encrypted.xml
  xml/ws4r-plain.xml
  xml/wss4r-signed-encrypted.xml
  xml/wss4r-signed.xml
  xml/wss4r-usernametoken.xml
  xml/xws-encrypted-signed-client.xml
  xml/xws-encrypted.xml
  xml/xws-signed-encrypted-client.xml
  xml/xws-signed-encrypted-server.xml
  xml/xws-signed-encrypted-server20.xml
  xml/xws-signed.xml
  xml/xws-usernametoken.xml
}

Gem::Specification.new do |s|
  s.name = "wss4r"
  s.version = "0.5.0"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["Roland Schmitt"]

  s.date = "2005-12-22"
  s.description = "Partial implementation of some of the WS-Security standards on top of SOAP4R."
  
  s.files = WSS4R_FILES
  
  s.has_rdoc = false
  s.homepage = "http://rubyforge.org/projects/wss4r/"
  s.require_paths = ["lib", "xml"]
  s.rubyforge_project = "wss4r"
  s.rubygems_version = "1.3.5"
  s.summary = "Partial implementation of some of the WS-Security standards on top of SOAP4R."

  s.add_dependency("rubigen", [">= 1.0.6"])
  s.add_dependency("log4r", [">= 1.0.5"])
end