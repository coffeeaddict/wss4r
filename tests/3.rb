require "openssl"
require "rexml/document"
require "base64"

include OpenSSL
include Cipher
include PKey
include X509
include REXML

key = nil
iv  = nil
alg = "DES-EDE3-CBC"
certificate = Certificate.new(File.read("certs/server.cer"))
public_key = certificate.public_key()
private_key = RSA.new(File.read("certs/server.key"))
text = "1234567" # ist ein Probetext."
text='<ns0:Ping xmlns:enc="http://schemas.xmlsoap.org/soap/encoding/" xmlns:env="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ns0="http://xmlsoap.org/Ping" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><ns0:ticket xmlns:ans1="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" ans1:Id="Id">SUNW</ns0:ticket><ns0:text>Sun Microsystems says hello scenario 3!</ns0:text></ns0:Ping>"'

puts("Encryption-------\n")
des = Cipher.new(alg)
key = des.random_key()
iv = des.random_iv()
des.encrypt(key, iv)
des.key = key
des.iv=iv
cipher = des.update(text)
cipher << des.final()

puts("Ciphertext------")
puts(cipher)
puts("Decryption-------\n")

des2 = Cipher.new(alg)
des2.decrypt(key, iv)
des2.iv=iv
des2.key=key
plain = des2.update(cipher)
plain << des2.final()
puts("Plaintext-------\n" + plain)






#symm_cipher = cipher
#puts("symm_cipher: " + symm_cipher)
#puts("iv+key: " + (iv+key))
#cipher = public_key.public_encrypt(iv+key)
#cipher = encode64(cipher)
#puts("chiffrat: " + cipher.to_s())
#puts("key     : " + encode64(key))
#puts("iv      : " + encode64(iv))
#puts("iv+key  : " + encode64(iv+key))
#puts("------------------------------------------------")
#
##-------------------------------------------------------------
##-------------------------------------------------------------
##-------------------------------------------------------------
#
#encipher = decode64(cipher)
#encipher = private_key.private_decrypt(encipher)
#puts("symm. decrypted: " + encipher)
##encipher = decode64(encipher)
##puts("iv+key: " + encipher)
#iv2 = encipher[0..7]
#key2 = encipher[8..-1]
##puts("chiffrat: " + encipher.to_s())
#puts("key     : " + encode64(key2))
#puts("iv      : " + encode64(iv2))
#puts("iv+key  : " + encode64(iv2+key2))
#
#des2 = Cipher.new(alg)
##des2.decrypt(key2, iv2)
#des2.iv=iv2
#des2.key=key2
#puts("symm_cipher: " + symm_cipher)
#plain = des2.update(symm_cipher)
#plain << des2.final()
#puts("encipher: " + plain)
#
#
#
#
#
