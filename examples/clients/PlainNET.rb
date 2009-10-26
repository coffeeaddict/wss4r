require "soap/rpc/driver"
require "breakpoint"
include SOAP::RPC

class Test
   def initialize()
		@driver = Driver.new('http://127.0.0.1:8070/WebService/Service1.asmx','http://localhost/WebService/')
      #@driver.default_encodingstyle = SOAP::EncodingStyle::ASPDotNetHandler::Namespace
		@driver.add_method_with_soapaction('SayHello','http://localhost/WebService/SayHello','name')
      puts("Ergebnis: " + @driver.SayHello("Mike"))
	end
end

Test.new()
