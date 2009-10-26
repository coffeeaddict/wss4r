require "wss4r/tokenresolver/certificateresolver"
require "openssl"
require "base64"

include OpenSSL
include X509
include Cipher
include PKey

rsa_encrypted_symm_key = Base64.decode64("CzqGr0J3r1HHhWVisSZpIVZNmx7u8VLEybV0HAO+LzSKUFuvqOdwcPSYGVQmtoK/X8C9po8fnS5UK40L5V98wNz+TYl9v8nOXgg/0W7w3Mx8Y7h6MnJx2ge5rAr92xQcGE9uzQl9Zh6IiEhplsxk1x9H+27sajhUpnQ5nee7CvI=")
triple_des_encrypted_body = Base64.decode64("8nR2RddaSIWgOxKKjFNcxxufpxZS9B16jftUh4dXJa0G6C3XBA+mQMo7wayNhrgaQeNvUfIFIIQTrqe+rSU5irzzGfrdBg2S2ssnmwWy+AVUhN16qjSiGCPIyWgu9OZKr+RuWeSRjVp8z3YtH5f47wGuvY2BmQ48lydFi6QvQMY2Wvb4D9gLjWg8GE1uybpgSbMBjLFJKDajjllDWsKT255GGDPdYR9BfZ9VpTiI9eNz1fa9xoZu+Q==")

x509 = Certificate.new(File.read("certs/xws-server-cert.cer"))
pkey = RSA.new(File.read("certs/xws-server-key.pem"))
puts(pkey.to_s())

iv = triple_des_encrypted_body[0..7]

c = WSS4R::Tokenresolver::CertificateDirectoryResolver.new("./certs")
cert = c.get_certificate_by_key_identifier("tUYo1KhZtRDiUf1LVNDUopTczmo=")
key = c.get_private_key(cert)

key = pkey.private_decrypt(rsa_encrypted_symm_key)

des = Cipher.new("DES-EDE3-CBC")
      
des.decrypt(key, iv)
des.key = key
des.iv = iv
cipher = des.update(triple_des_encrypted_body[8..-1])
cipher << des.final()

puts(cipher)
