require "soap/rpc/driver"
require "soap/soap"
require "soap/processor"
require "wss4r/security/security"
require "wss4r/soap/processor"
require "wss4r/rpc/proxy"
require "wss4r/rpc/router"

include SOAP

module SOAP
   module RPC
      class Driver 
         def security()
            @proxy.security()
         end  
      end
   end
end
