require "wss4r/security/signing/signed_info"
require "rexml/document"

include WSS4R::Security::Signing

doc = Document.new(File.new(ARGV[0]))
signed_info = SignedInfo.new()
doc = signed_info.get_xml(doc)
puts("Ergebnis ------")
puts(doc)