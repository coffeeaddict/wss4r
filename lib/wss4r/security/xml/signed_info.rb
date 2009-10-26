module WSS4R
  module Security
    module Xml

      class SignedInfo
	attr_accessor :canonicalizer_method, :signature_method

	def initialize()
          @reference_elements = ReferenceElements.new()
	end
	
	def process(parent)
          @par = parent
          body = SOAPParser.part(SOAPParser::BODY)
          body.add_namespace("xmlns:wsu", Namespaces::WSU)
          signed_info_element = parent.add_element(Names::SIGNED_INFO)
          canonicalization_element = signed_info_element.add_element(Names::CANONICALIZATION_METHOD)
          canonicalization_element.add_attribute("Algorithm", Types::CANON_C14N_EXCL)
          signature_method_element = signed_info_element.add_element(Names::SIGNATURE_METHOD)
          signature_method_element.add_attribute("Algorithm", Types::SIG_ALG_RSA_SHA1)
          @reference_elements.each{|xpath|
            element = parent.document.select(xpath)
            wsu_id = nil
            element.attributes().each_attribute{|attr|
              wsu_id = attr if (attr.name() == "Id") #attr.prefix() == "wsu" && 
            }
            if (wsu_id == nil)
              wsu_id = REXML::Attribute.new("wsu:Id", element.object_id().to_s())
              element.add_attribute(wsu_id)
            end
            canonicalizer = TransformerFactory::get_instance(nil)
            c14n_element = canonicalizer.canonicalize_element(element)
            reference_element = signed_info_element.add_element(Names::REFERENCE_DS)
            reference_element.add_attribute("URI","#"+wsu_id.value())
            transforms_element = reference_element.add_element(Names::TRANSFORMS)
            transform_element = transforms_element.add_element(Names::TRANSFORM)
            transform_element.add_attribute("Algorithm", Types::CANON_C14N_EXCL)
            digest_method_element = reference_element.add_element(Names::DIGEST_METHOD)
            digest_method_element.add_attribute("Algorithm", Types::DIG_METHOD_SHA1)
            digest_value_element = reference_element.add_element(Names::DIGEST_VALUE)
			
            sha = OpenSSL::Digest::SHA1.new(c14n_element)
            #Bug from Tony Baines
            digest_value_element.text=(Base64.encode64(sha.digest()))
          }
          signed_info_element
	end

	def unprocess(document)
          @reference_list = Array.new()
		
          signed_info = XPath.first(document, "//ds:SignedInfo", {"ds" => Namespaces::DS})
		
          inclusive_namespaces = XPath.first(signed_info, "ds:CanonicalizationMethod/InclusiveNamespaces", {"ds" => Namespaces::DS})
          prefix_list = inclusive_namespaces.attribute("PrefixList") if (inclusive_namespaces)
          if (prefix_list)
            prefix_list = prefix_list.value().split()
          end
		
          canonicalization_method = XPath.first(signed_info, Names::CANONICALIZATION_METHOD)
          @canonicalization_method = canonicalization_method.attribute("Algorithm").value()
		
          signature_method = XPath.first(signed_info, Names::SIGNATURE_METHOD)
          @signature_method = signature_method.attribute("Algorithm")
		
          signed_info.each_element("ds:Reference"){|reference|
            @reference_list.push(Reference.new(reference, prefix_list))
          }
	end
	
	def verify()
          @reference_list.each{|reference|
            if (reference.verify() == false)
              fault = SOAP::SOAPFault.new(SOAP::SOAPString.new("wsse:FailedCheck"), SOAP::SOAPString.new("The signature or decryption was invalid."),SOAP::SOAPString.new(self.class().name())) #,"Error verifying reference: " + reference.uri())
              raise SOAP::FaultError.new(fault)
            end
          }
	end
      end

    end #Xml
  end #Security
end #WSS4R
