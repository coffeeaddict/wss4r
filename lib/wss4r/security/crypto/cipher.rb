module WSS4R
  module Security
    module Crypto
	
      class SymmetricEncrypter
        def initialize(algorithm, key = nil, iv = nil)
          @cipher = Cipher.new(algorithm)
          @algorithm = algorithm
          if (iv == nil)
            @iv = @cipher.random_iv()
          else
            @iv = iv
          end
          if (key == nil)
            @key = @cipher.random_key()
          else
            @key = key
          end
        end
   
        def encrypt_to_b64(text)
          @cipher.encrypt(@key, @iv)
          @cipher.key = @key
          cipher = @cipher.update(text)
          cipher << @cipher.final()
          Base64.encode64(cipher)
        end
   
        def decrypt(text)
          @cipher.decrypt(@key, @iv)
          @cipher.key = @key
          @cipher.iv = @iv
          cipher = @cipher.update(text[8..-1])
          cipher << @cipher.final()
          cipher    
        end
   
        def iv()
          @iv
        end
	
        def key()
          @key
        end
	
        def key=(key)
          @key
        end
	
        def iv_b64()
          Base64.encode64(@iv)
        end
   
        def key_b64()
          Base64.encode64(@key)
        end
      end

      class TripleDESSymmetricEncrypter < SymmetricEncrypter
        def initialize(key = nil, iv = nil)
          @cipher = Cipher.new("DES-EDE3-CBC")
          if (iv == nil)
            @iv = @cipher.random_iv()
          else
            @iv = iv
          end
          if (key == nil)
            @key = @cipher.random_key()
          else
            @key = key
          end
        end
   
        def decrypt(text)
          @cipher.decrypt(@key, @iv)
          @cipher.key = @key
          @cipher.iv = @iv
          cipher = @cipher.update(text[8..-1])
          cipher << @cipher.final()
          cipher    
        end
   
        def algorithm()
          Types::ALGORITHM_3DES_CBC
        end
	
        def iv=(text_iv)
          @iv = text_iv[0..7]
        end
      end

      class AESSymmetricEncrypter < SymmetricEncrypter
        def initialize(key = nil, iv = nil)
          @cipher = Cipher.new(self.cipher_name)
          if (iv == nil)
            @iv = @cipher.random_iv()
          else
            @iv = iv
          end
          if (key == nil)
            @key = @cipher.random_key()
          else
            @key = key
          end
        end
   
        def decrypt(text)
          @cipher.decrypt(@key, @iv)
          @cipher.key = @key
          @cipher.iv = @iv
          cipher = @cipher.update(text[16..-1])
          cipher << @cipher.final()
          cipher    
        end
   
        def algorithm()
          Types::ALGORITHM_AES_CBC
        end
        
        def cipher_name()
          "AES-256-CBC"
        end
         
        def iv=(text_iv)
          @iv = text_iv[0..15]
        end
      end

      class AES128SymmetricEncrypter < AESSymmetricEncrypter
        def initialize(key = nil, iv = nil)
          super(key, iv)
        end
        
        def algorithm()
          Types::ALGORITHM_AES128_CBC
        end
        
        def cipher_name()
          "AES-128-CBC"
        end
      end

      class AsymmetricEncrypter
        def initialize(filename)
          @private_key = RSA.new(File.read(filename))
        end
   
        def decrypt_symmetrickey_from_b64(text)
          ciphertext  = @private_rsa_key.private_decrypt(text)
          iv = ciphertext[0..7]
          key = ciphertext[8..-1]
          symmetric_key = Cipher.new(@symmetric_algorithm)
          symmetric_key.decrypt(key, iv)
          symmetric_key.key = key
          symmetric_key
        end
      end

    end #Crypto
  end #Security
end #WSS4R