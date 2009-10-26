require "openssl"
require "rexml/document"
require "base64"

include REXML
include OpenSSL
include X509
include Cipher

class DecryptXML
  def initialize(filename)
    doc = Document.new(File.read(filename))
    element = XPath.first(doc, "/soap:Envelope/soap:Header/wsse:Security/wsse:BinarySecurityToken")
    @cert = Certificate.new(decode64(element.text()))

    element = XPath.first(doc, "/soap:Envelope/soap:Header/wsse:Security")
    element1 = XPath.first(element,"xenc:EncryptedKey")
    element2 = XPath.first(element, "wsse:BinarySecurityToken")

    #Hack!----
    nodes = XPath.match(doc, "/soap:Envelope/soap:Header/wsse:Security/*")
    encrypted_key = nodes[1]
    cipher_value = encrypted_key.elements["xenc:CipherData"].elements["xenc:CipherValue"].text()
    @rsa_3des_key = decode64(cipher_value)
    #----------------------------------------------------------------------------
    encrypted_body = XPath.first(doc, "/soap:Envelope/soap:Body/xenc:EncryptedData/xenc:CipherData/xenc:CipherValue")
    @des_cipher = decode64(encrypted_body.text())
    
    puts("\nCertiticate:\n",@cert.to_text(),"\n")
    puts("\nRSA-3DES-Key:\n",@rsa_3des_key,"\n")
    puts("\n3DES-Cipher: \n",@des_cipher,"\n")
 end
end

#e = doc.elements["soap:Envelope"].elements["soap:Header"].elements["wsse:Security"]

dec = DecryptXML.new("msClient.xml")

#cert_string = decode64(File.read("cert_string.txt"))
#cert = Certificate.new(cert_string)
#puts(cert.to_text())
