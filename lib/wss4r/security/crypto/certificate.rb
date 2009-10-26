module OpenSSL
module X509
	
class Certificate
   def key_identifier()
		ext = extensions.find {|e| e.oid == 'subjectKeyIdentifier' }
		key_identifier = Base64.encode64(ext.to_der()[11..30])
		return key_identifier.gsub("\n","")
   end
	
   def filename()
      return @filename
   end
	
   def filename=(filename)
      @filename = filename
   end
end

end
end
