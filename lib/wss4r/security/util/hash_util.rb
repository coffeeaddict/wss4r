require "base64"

module WSS4R
module Security
module Util

class HashUtil
	def HashUtil::hash_encode64(value)
		#zwei chr sind ein Hex-Wert
		#wenn positiv -> passt
		#wenn negativ -> wert = 256+chr_wert
		j=0
		ret = (" " * (value.size()/2))
		0.step((value.size()-1),2) {|i|
			hex = value[i..i+1].hex()
			if (hex > 0)
				ret[j] = hex
			elsif
				ret[j] = 256+(hex)
			end
			j=j+1
		}
		Base64.encode64(ret)
	end
	
	def HashUtil::byte_array(string)
		ret=""
		0.upto(string.size()-1) {|i|
			ret = ret + string[i].to_s() + ","
		}
		ret=ret[0..-2]
		ret
	end
end


end #Util
end #Security
end #WSS4R