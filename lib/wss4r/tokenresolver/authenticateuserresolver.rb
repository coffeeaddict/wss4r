module WSS4R
	
  module Tokenresolver
    class AuthenticateUserResolver < Resolver
		
      def authenticate_user(usernametoken)
        puts (usernametoken)
        if usernametoken.type() == UsernameToken::HASHED
          stamp = Base64.decode64(usernametoken.nonce())+usernametoken.created()
          stamp = stamp + authenticate_token(usernametoken)
          hash = CryptHash.new().digest_b64(stamp)
          return hash.to_s() == usernametoken.hash().to_s()
        else
          return authenticate_token_plain(usernametoken.username(), usernametoken.password())
        end
        false
      end
    end
	
    def authenticate_token(usernametoken)
      usernametoken.username().reverse()
    end
	
    def authenticate_token_plain(username, password)
      @username = username
      @password = password
      return (username.reverse() == password)
    end
	
  end	#Tokenresolver
end	#WSS4R
			
			

