require "wss4r/rpc/wssdriver"

include SOAP::RPC

class Test
	
	def initialize(mode)
		@driver = Driver.new('http://localhost:8080/','urn:mal')
		@driver.add_method('mal','a','b')

		puts("Ergebnis: " + @driver.mal(10,30).to_s())
	end
	
end

Test.new(ARGV)
