require "rexml/document"
include REXML

doc = Document.new(File.read("../xml/wse-answer.xml"))

e = XPath.first(doc, "//soap:Envelope//soap:Header//wsse:Security//wsu:Timestamp")

puts(e.to_s())

puts("---------------------------------------------------------------------------------------------------------------")

s = XPath.match(e, "//xenc:CipherValue")
puts(s[0])