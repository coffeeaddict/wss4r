module WSS4R
module Security
module Util
	
class ReferenceElements < Array
	def initialize()
				push("/env:Envelope/env:Header/wsse:Security/wsu:Timestamp")
		push("/env:Envelope/env:Body")

	end
end

end #Util
end #Security
end #WSS4R