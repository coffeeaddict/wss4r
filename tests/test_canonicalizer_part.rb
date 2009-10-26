require "wss4r/security/util/xmlcanonicalizer"
require "openssl"
require "base64"

include WSS4R::Security::Util

xml = '<Timestamp xmlns="http://www.w3.org/2000/09/xmldsig#">
            <Created>2005-03-16T12:33:32Z</Created>
            <Expires>2005-03-16T12:38:32Z</Expires>
         </Timestamp>'

document = Document.new(xml)

c = XmlCanonicalizer.new(true, true)
result = c.canonicalize(document)
                              
sha = OpenSSL::Digest::SHA1.new(result)
puts("Hash: " + Base64.encode64(sha.digest()))