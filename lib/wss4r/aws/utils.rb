require "wss4r/soap/processor"
require "wss4r/tokenresolver/resolver"
require "wss4r/tokenresolver/authenticateuserresolver"
require "wss4r/tokenresolver/certificateresolver"

include WSS4R
include WSS4R::Tokenresolver

module ActionWebService # :nodoc:
	module Container # :nodoc:
		module ActionController # :nodoc:
			module ClassMethods
				@@initialized_resolver = false
				@@initialized_tokens = false
				def security()
					SOAP::Processor::security()
				end
				def wss_add_resolvers(resolvers)
					if !(@@initialized_resolver)
						resolvers.each{|resolver|
							security().add_security_resolver(resolver)
						}
						@@initialized_resolver = true
					end
				end
				def wss_add_security_tokens(tokens)
					if !(@@initialized_tokens)
						tokens.each{|token|
							security().add_security_token(token)
						}
						@@initialized_tokens = true
					end
				end
			end
		end
	end
end
