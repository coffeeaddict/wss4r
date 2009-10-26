require "wss4r/config/config"
require "wss4r/security/security"
require "pp"

include WSS4R
include Security

module SOAP
  module Header
    class HandlerSet
      def on_inbound(headers)
        headers.each do |name, item|
          handler = @store.find { |handler|
            handler.elename == item.element.elename
          }
          if handler
            handler.on_inbound_headeritem(item)
          elsif item.mustunderstand
            #raise UnhandledMustUnderstandHeaderError.new(item.element.elename.to_s)
          end
        end
      end
    end
  end
	
  module Processor
    class << self
      public 
      alias old_marshal marshal
      alias old_unmarshal unmarshal
			
      def security=(s)
        @@security = s
      end
      def security()
        @@security = WSS4R::Security::Security.new() if (!defined?(@@security))
        @@security
      end
			
      def config()
        store = WSS4R::Config::Store.new()
        config = store.load()
        if (config != nil)
          @security = WSS4R::Security::Security.new()
          config.build_security(@security)
        end
      end
			
      def marshal(env,opt = {}, io = nil)
        #config()
        xml = Processor.old_marshal(env, opt, io)

        security = opt[:security]
        if (defined?(@@security) && @@security != nil)
          security = @@security if (@@security)
        end
        document = Document.new(xml)
        if (security != nil)
          security.process_document_marshal(document)
        end
        document.to_s()
      end
         
      def unmarshal(stream, opt = {})
        #config()
        security = opt[:security] 
        if (defined?(@@security) && @@security != nil)
          security = @@security if (@@security)
        end
        doc = Document.new(stream)
        if (security != nil)
          SOAPParser::document=(doc)
          soap_ns = doc.root().prefix()
          wsseElement = SOAPParser.part(SOAPParser::SECURITY)
          if (wsseElement != nil)
            security.process_document_unmarshal(doc)
            if (wsseElement.parent() != nil)
              wsseElement.parent().delete_element(wsseElement)
            end
          else
            #TODO: What to do when no security tokens in header?
            #if security.tokens().size() > 0
             # raise Exception.new("No security elements received!")
            #end
          end
        end
        xml = Processor.old_unmarshal(doc.to_s(), opt)
        xml
      end
    end
  end
end
