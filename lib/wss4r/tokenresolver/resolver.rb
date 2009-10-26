module WSS4R
  module Tokenresolver
    class Resolver
      def certificate_by_subject(subject)
      end
      def private_key(certificate)
      end
      def authenticate_user(usernametoken)
        return false
      end
    end
  end
end