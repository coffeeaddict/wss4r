require "rexml/document"
require "openssl"
require "base64"

include OpenSSL
include X509
include Cipher
include PKey

include REXML

include Base64

class DecryptMessage
   def initialize(document, cert, key, sessionkey)
      @document = document
      @cert = cert
      @private_key = key
      @sessionkey = sessionkey      
   end
   
   def encrypt()
      text='<ns0:Ping xmlns:enc="http://schemas.xmlsoap.org/soap/encoding/" xmlns:env="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ns0="http://xmlsoap.org/Ping" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><ns0:ticket xmlns:ans1="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" ans1:Id="Id">SUNW</ns0:ticket><ns0:text>Sun Microsystems says hello scenario 3!</ns0:text></ns0:Ping>"'
      puts("Encryption-------\n")
      des = Cipher.new("DES-EDE3-CBC")
      cipherValue = XPath.first(@document, "/env:Envelope/env:Body/xenc:EncryptedData/xenc:CipherData/xenc:CipherValue")
      cipherValueText = 'PG5zMDpQaW5nIHhtbG5zOmVuYz0iaHR0cDovL3NjaGVtYXMueG1sc29hcC5vcmcvc29hcC9lbmNvZGluZy8iIHhtbG5zOmVudj0iaHR0cDovL3NjaGVtYXMueG1sc29hcC5vcmcvc29hcC9lbnZlbG9wZS8iIHhtbG5zOm5zMD0iaHR0cDovL3htbHNvYXAub3JnL1BpbmciIHhtbG5zOnhzZD0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEiIHhtbG5zOnhzaT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEtaW5zdGFuY2UiPjxuczA6dGlja2V0IHhtbG5zOmFuczE9Imh0dHA6Ly9kb2NzLm9hc2lzLW9wZW4ub3JnL3dzcy8yMDA0LzAxL29hc2lzLTIwMDQwMS13c3Mtd3NzZWN1cml0eS11dGlsaXR5LTEuMC54c2QiIGFuczE6SWQ9IklkIj5TVU5XPC9uczA6dGlja2V0PjxuczA6dGV4dD5TdW4gTWljcm9zeXN0ZW1zIHNheXMgaGVsbG8gc2NlbmFyaW8gMyE8L25zMDp0ZXh0PjwvbnMwOlBpbmc+'
      iv = Base64.decode64(cipherValue.text())
      iv = iv[0..7]
      key = @sessionkey
      des.encrypt(key, iv)
      des.key = key
      des.iv=iv
      cipher = des.update(cipherValueText)
      cipher << des.final()
      puts("Encrypted text-------\n")
      puts(cipher)
      puts("\nLänge:" + cipher.size().to_s())
      puts("---------------------")
      puts(Base64.encode64(cipher))
      f = File.new("../../WSS4Rjava/data/ruby_encrypted_b64","w")
      f.write(Base64.encode64(cipher))
      f.close()
      f = File.new("../../WSS4Rjava/data/ruby_encrypted","w")
      f.write(cipher)
      f.close()
   end

   def encrypt_sessionkey()
      #cipherKey = XPath.first(@document, "/soap:Envelope/soap:Header/wsse:Security/xenc:EncryptedKey/xenc:CipherData/xenc:CipherValue").text()
      cipherKey = XPath.match(@document, "//xenc:CipherValue")[0].text()
      puts(cipherKey)
      @sessionkey = @private_key.private_decrypt(Base64.decode64(cipherKey))
      @sessionkey
   end

   
   def extract_key_iv_text(document, key_filename, iv_filename, text_filename)
      cipherValue = Base64.decode64(XPath.first(document, "/env:Envelope/env:Body/xenc:EncryptedData/xenc:CipherData/xenc:CipherValue").text())
      
      element = XPath.first(document, "/env:Envelope/env:Body/xenc:EncryptedData/xenc:CipherData/xenc:CipherValue").text()
      
      iv = cipherValue[0..7] 
      text = cipherValue[8..-1]
      key = @sessionkey
      
      iv_file = File.new(iv_filename,"w")
      key_file = File.new(key_filename,"w")
      plaintext_file = File.new(text_filename,"w")
      base64text_file = File.new(text_filename+"_b64", "w")
      
      iv_file.print(Base64.encode64(iv))
      key_file.print(Base64.encode64(key))
      plaintext_file.print(Base64.decode64(cipherValue))
      base64text_file.print(element)
      
      iv_file.close()
      key_file.close()
      plaintext_file.close()
      base64text_file.close()
   end
   
   def decrypt_body()
      #cipherValue = Base64.decode64(XPath.first(@document, "/env:Envelope/env:Body/xenc:EncryptedData/xenc:CipherData/xenc:CipherValue").text())
      cipherValue = 'Y2dm1kJ0aSYa767SrCasxcUCMwV2BXs8hVEe6O4yyRuyvx2mDZZDfnS7v02hX1Uth+NN8TwU09IkbX85YV/C1p03voPDSqKBCKuF+Hrmi0ldavfaY+4yO3YKWxGpPUtIxLpgfZ237JcCZ2+P7dntb7K/6mthCL1LCLJ4QnAmCRGd20J0qKjYJgLqWciojH80zMtjwWnYW3sJmHpi0OqOCx4TcH32wn9RJiNG06QKfz0G3mu5fIFFQWdfmDIqtPTQKc0Ggv5cCxYOA5FW1CSuXKfx+TJy9flL'
      iv = cipherValue[0..7]
      text = cipherValue[8..-1]
      des = Cipher.new("DES-EDE3-CBC")
      
      key = @sessionkey
      des.decrypt(key, iv)
      des.key = key
      des.iv = iv
      cipher = des.update(text)
      cipher << des.final()
      cipher    
   end
end

doc = Document.new(File.read("../xml/wse-response.xml"))
cert = Certificate.new(File.read("../certs/xws-client-cert.cer"))
private_key = RSA.new(File.read("../certs/xws-client-key.pem"))

message = DecryptMessage.new(doc, cert, private_key, nil)
sessionkey = message.encrypt_sessionkey()
puts(message.decrypt_body())


