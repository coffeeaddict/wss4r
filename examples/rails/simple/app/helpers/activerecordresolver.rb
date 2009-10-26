class ActiveRecordResolver < WSS4R::Tokenresolver::AuthenticateUserResolver
	
	def private_key(certificate)
		subject = certificate.subject().to_s()
		pkey = Key.find_by_subject(subject)
		return nil if !pkey
		key = OpenSSL::PKey::RSA.new(Base64.decode64(pkey.private_key))
		return key
	end
	
	def certificate_by_subject(subject)
		c = Key.find_by_subject(subject)
		cert = OpenSSL::X509::Certificate.new(Base64.decode64(c.cert_data()))
		cert
	end
	
	def authenticate_token(token)
		token.username().reverse()
	end
end
