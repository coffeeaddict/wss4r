require "wss4r/security/signing/key_info"
require "wss4r/security/tokens/tokentypes"
require "wss4r/security/util/xmlutils"

require "rexml/document"
require "openssl"

include WSS4R::Security::Signing
include WSS4R::Security::Tokens
include OpenSSL

x509 = X509SecurityToken.new(OpenSSL::X509::Certificate.new(File.new(ARGV[1])))

doc = Document.new(File.new(ARGV[0]))
key_info = KeyInfo.new(x509, KeyInfo::REFERENCE)
signature_element = doc.select(doc, "/env:Envelope/env:Header/wsse:Security")
key_info.get_xml(signature_element)
puts("Ergebnis ------")
puts(doc)