require "time"
require "wss4r/security/util/xmlcanonicalizer"
require "wss4r/security/util/hash_util"
require "openssl"
require "base64"
require "breakpoint"
require "wss4r/security/util/types"
require "wss4r/security/xml/tokentypes"

include WSS4R::Security::Util
include WSS4R::Security::Xml

document = Document.new(File.new(ARGV[0]))
type = ARGV[1]

element = XPath.match(document, "/env:Envelope/env:Body")[0] if (type == "body")
element = XPath.match(document, "/child::env:Envelope/child::env:Header/child::wsse:Security/child::wsu:Timestamp")[0] if (type == "timestamp")
#element = XPath.match(document, "/child::env:Envelope/child::env:Header/child::wsse:Security")[0][1][1] if (type=="signed_info") #für XWS
element = XPath.match(document, "/child::env:Envelope/child::env:Header/child::wsse:Security")[0][1][0] if (type=="signed_info") #für WSS4R
#breakpoint

f=File.new("out-before-ruby.xml","wb")
f.write(element)
f.close()

c = XmlCanonicalizer.new(false, true)
#result = c.write_document_node(element)
result = c.canonicalize_element(element)
puts("Input-----------------------------------")
puts(element.to_s())
puts("----------------------------------------")
puts("Output----------------------------------")
puts(result)
puts("----------------------------------------")
f=File.new("out-after-ruby.xml","wb")
f.write(result)
f.close()

array = HashUtil::byte_array(result.to_s())
sha = OpenSSL::Digest::SHA1.new(result)
hash=HashUtil::hash_encode64(sha.to_s())
puts("Util: " + hash)
puts("Hash: " + Base64.encode64(sha.digest()))


######################

=begin
cert = OpenSSL::X509::Certificate.new(File.read("certs/neu-xws-client-cert.b64.cer"))
pkey = OpenSSL::PKey::RSA.new(File.read("certs/neu-xws-client-key.pem"))
x509 = X509SecurityToken.new(cert,pkey)
signature_value = x509.sign_b64(result)
puts("#######################")
puts(signature_value)
=end
