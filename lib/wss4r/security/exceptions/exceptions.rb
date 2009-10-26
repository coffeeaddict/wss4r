module WSS4R
  module Security
    module Exceptions

      class FaultString
	attr_reader :data
	def initialize(data)
          @data = data
	end
      end
		
      class WSS4RFault < SOAP::FaultError
	attr_accessor :faultcode, :faultstring, :faultactor, :detail 
	
	def initialize(faultcode,faultstring,faultactor,detail)
          @faultcode = faultcode
          @faultstring = FaultString.new(faultstring)
          @faultactor = faultactor
          @detail = detail
	end
      end

      class VerificationFault < WSS4RFault
	def initialize()
          @faultcode = "100"
          @faultstring = FaultString.new("Signature not valid!")
          @faultactor = "test"
          @detail = "Signature verification failed."
	end	
      end

      class TimestampFault < WSS4RFault
	def initialize()
          @faultcode = "101"
          @faultstring = FaultString.new("Timestamp not valid")
          @faultactor = "test"
          @detail = "Timestamp verification failed."
	end
      end

      class UsernameTokenFault < WSS4RFault
  	def initialize()
          @faultcode = "102"
          @faultstring = FaultString.new("UsernameToken not valid")
          @faultactor = "test"
          @detail = "UsernameToken verification failed."
	end
      end
      
      class NoSecurityFault < WSS4RFault
  	def initialize()
          @faultcode = "103"
          @faultstring = FaultString.new("No security token received.")
          @faultactor = "test"
          @detail = "No security token received."
	end
      end

    end #WSS4R
  end #Security
end #Exceptions

