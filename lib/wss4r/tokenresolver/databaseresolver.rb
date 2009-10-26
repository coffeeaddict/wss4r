require "sqlite3"
require "openssl"

require "base64"

require "wss4r/tokenresolver/resolver.rb"
require "wss4r/security/crypto/certificate"

include OpenSSL::PKey
include OpenSSL::X509

module WSS4R
module Tokenresolver
   class DatabaseResolver < Resolver
      def initialize(database_file)
			@db = SQLite3::Database.new(database_file)
      end
		
      def private_key(certificate)
			cert_data = Base64.encode64(certificate.to_der())
			select = "select * from certificates where cert_data = '#{cert_data}'"
			rows = @db.execute(select)
			return nil if (rows == nil || rows.size() == 0) 
			private_key_data = rows[0][3]
			private_key_data = Base64.decode64(private_key_data)
			private_key = RSA.new(private_key_data)
			return private_key if private_key
			return nil
      end
		
		def certificate_by_subject(subject)
			select = "select * from certificates where subject = '#{subject}'"
			rows = @db.execute(select)
			return nil if (rows == nil || rows.size() == 0)
			cert_data = rows[0][2]
			cert_data = Base64.decode64(cert_data)
			cert = Certificate.new(cert_data)
			return cert if cert
			return nil
		end
   end
end
end

if __FILE__ == $0
	resolver = WSS4R::Tokenresolver::DatabaseResolver.new(ARGV[0])
	cert = resolver.certificate_by_subject("/C=DE/ST=Rheinland-Pfalz/L=Trier/O=FF/OU=Developement/CN=Client/emailAddress=client@web.de")
	key = resolver.private_key(cert)
	puts("Certificate:----" + cert.to_s())
	puts("Private key:----" + key.to_s())
end


#cert = c.get_certificate_by_key_identifier("tUYo1KhZtRDiUf1LVNDUopTczmo=")
#key = c.get_private_key(cert)
#puts(key.to_s())
