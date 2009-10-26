require "soap/rpc/driver"
require "breakpoint"

include SOAP::RPC

class Test
   def initialize()
		@driver = Driver.new('http://localhost:8080/securesimple/Ping',"http://xmlsoap.org/Ping")
		@driver.generate_explicit_type=false
		@driver.add_method('Ping', 'ticket', 'text')
      puts("Ergebnis: ", @driver.Ping("SUNW","Toller Test!"))
	end
end

Test.new()
