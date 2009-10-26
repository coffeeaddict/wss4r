require "wss4r/security/signing/signature"
require "wss4r/security/tokens/tokentypes"
require "wss4r/security/util/xmlutils"

require "rexml/document"

include WSS4R::Security::Signing
include WSS4R::Security::Tokens
include OpenSSL

pkey = OpenSSL::PKey::RSA.new(File.new(ARGV[2]))
x509 = X509SecurityToken.new(OpenSSL::X509::Certificate.new(File.new(ARGV[1])), pkey)

doc = Document.new(File.new(ARGV[0]))
signature = Signature.new(x509)
document = signature.get_xml(doc)

puts("Ergebnis ------")
puts(doc)