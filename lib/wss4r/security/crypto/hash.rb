require "openssl"
include OpenSSL
include OpenSSL::Digest


module WSS4R
  module Security
    module Crypto

      class CryptHash

	def initialize(type = "SHA1")
          @digest = SHA1.new() if (type == "SHA1")
          @digest = MD5.new()  if (type == "MD5")
	end
	
	def digest(value)
          @digest.update(value)
          return @digest.digest()
	end
	
	def digest_b64(value)
          digest = self.digest(value)
          return Base64.encode64(digest)
	end
	
	def to_s()
          return @digest.to_s()
	end
      end

    end
  end
end

