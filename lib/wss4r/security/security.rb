require "wss4r/security/xml/encrypted_key"
require "wss4r/security/xml/signature"
require "wss4r/security/xml/tokentypes"
require "wss4r/security/xml/encrypted_data"
require "wss4r/security/xml/reference_list"
require "wss4r/security/xml/security"
require "wss4r/security/xml/signed_info"
require "wss4r/security/xml/key_info"
require "wss4r/security/xml/signature_value"
require "wss4r/security/xml/reference"
require "wss4r/security/xml/timestamp"

require "wss4r/security/crypto/certificate"
require "wss4r/security/crypto/cipher"
require "wss4r/security/crypto/hash"

require "wss4r/security/util/transformer_factory"
require "wss4r/security/util/reference_elements"
require "wss4r/security/util/xmlcanonicalizer"
require "wss4r/security/util/namespaces"
require "wss4r/security/util/xmlutils"
require "wss4r/security/util/names"
require "wss4r/security/util/types"
require "wss4r/security/util/soap_parser"
require "wss4r/security/exceptions/exceptions"

require "wss4r/config/config"
require "wss4r/security/resolver"

require "time"
require "base64"
require "rexml/document"

require "soap/rpc/driver"
include SOAP

include OpenSSL
include OpenSSL::X509
include OpenSSL::Digest
include OpenSSL::Cipher
include OpenSSL::PKey

include WSS4R::Security::Xml
include WSS4R::Security::Util
include WSS4R::Security::Crypto
include WSS4R::Security::Exceptions


module WSS4R
  module Security
    
    class Security
      attr_reader :tokens
		 
      @@resolver = Resolver.new()
		 
      def initialize()
        @tokens = Array.new()
      end
		
      def add_security_token(token)
        @tokens.push(token)
      end
      
      def add_security_resolver(resolver)
        @@resolver.push(resolver)
      end 
      
      def clear_resolver!()
        @@resolver.clear()
      end
      
      def clear_tokens!()
        @tokens.clear()
      end
      
      def resolver()
        @@resolver
      end
			
      def process_document_marshal(document)
        return if (@tokens.size() == 0)
        SOAPParser.document=(document)
        
        document.root.add_namespace("xmlns:wsu", Namespaces::WSU)
        document.root.add_namespace("xmlns:wsse", Namespaces::WSSE)
        document.root.add_namespace("xmlns:wsa", Namespaces::WSA)
        document.root.add_namespace("xmlns:xenc", Namespaces::XENCD)
        document.root.add_namespace("xmlns:xsd", Namespaces::XSD)
        document.root.add_namespace("xmlns:xsi", Namespaces::XSI)
        root = document.root()
        soap_prefix = nil
        soap_ns=nil
        root.attributes.each_attribute() {|attr|
          if (attr.value() == Namespaces::S11)
            soap_prefix = attr.name()
            soap_ns = Namespaces::S11
          end
          if (attr.value() == Namespaces::S12)
            soap_prefix = attr.name()
            soap_ns = Namespaces::S12
          end
        }
        SOAPParser::soap_ns=(soap_ns)
        SOAPParser::soap_prefix=(soap_prefix)

        soap_body = XPath.first(document, "/env:Envelope/env:Body", {SOAPParser::soap_prefix => SOAPParser::soap_ns})
		  
        #soap_body = XPath.first(document, soap_prefix+":Envelope/"+soap_prefix+":Body")
        #soap_body = SOAPParser.part(SOAPParser::BODY)
        return if !soap_body 
        root.delete_element(soap_body)
        soap_header = SOAPParser.part(SOAPParser::HEADER)
        if (soap_header == nil) 
          soap_header = root.add_element(Names::HEADER)
        end
        root.add_element(soap_body)
        security = WSS4R::Security::Xml::Security.new()

        security.process(document)

        @tokens.each{|token|
          token.process(document)
        }
        ####Sort
        security = XPath.first(root, "/env:Envelope/env:Header/wsse:Security")#, {SOAPParser::soap_prefix=>SOAPParser::soap_ns})
        timestamp = XPath.first(security, "wsu:Timestamp")
        @t = timestamp
        @s = security
        children = security.children()
        children.each{|child|
          security.delete(child)
        }
        children.delete(timestamp)
        security.add_element(timestamp)
        children.each{|child|
          security.add_element(child)
        }
      end
      
      def process_document_unmarshal(document)
        security = WSS4R::Security::Xml::Security.new()
        security.unprocess(document)
      end
    end
    
  end #Security
end #WSS4R