require "soap/rpc/standaloneServer"
require "wss4r/security/security"
require "wss4r/rpc/wssdriver"

include WSS4R::Security

class SOAP::RPC::StandaloneServer
   def get_soaplet
      @soaplet
   end
end

module WSS4R
module Server

class WSSStandaloneServer < SOAP::RPC::StandaloneServer
   def security()
      security = get_soaplet().app_scope_router().security()
      if (security == nil) 
         security = WSS4R::Security::Security.new()
      end
      security
   end
end

end #Server
end #WSS4R
