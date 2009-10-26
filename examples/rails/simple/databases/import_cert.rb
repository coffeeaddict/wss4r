require "sqlite3"
require "openssl"
require "base64"

include OpenSSL
include X509
include PKey

DB_NAME = "keys.db"

def import(args)
	cert_file = args.shift()
	private_key_file = args.shift()

	cert = Certificate.new(File.new(cert_file))
	private_key = RSA.new(File.read(private_key_file))
	subject = cert.subject().to_s()

	cert = Base64.encode64(cert.to_der())
	private_key = Base64.encode64(private_key.to_s())

	db = SQLite3::Database.new(DB_NAME)
	e = "insert into keys (subject,cert_data, private_key) values ('#{subject}','#{cert}','#{private_key}')"
	db.execute(e)
end

def delete(subject)
	db = SQLite3::Database.new(DB_NAME)
	e = "delete from keys where subject ='#{subject}'"
	db.execute(e)
end   

command = ARGV.shift()
import(ARGV) if (command == "import")
delete(ARVG.shift()) if (command == "delete")




