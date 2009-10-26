module WSS4R
  module Security
    module Xml

      class Reference
	attr_reader :uri
	
	def initialize(element, prefix_list = nil)
          @ref_element = nil
          @transforms = Array.new()
          @prefix_list = prefix_list
          @uri = element.attribute("URI").to_s()[1..-1] #remove leading #
		
          elements = XPath.match(element, "Transforms/Transform", {"ds:" => Namespaces::DS})
          #element.each_element("ds:Transforms/ds:Transform"){|e|
          elements.each{|e|
            @transforms.push(e.attribute("Algorithm"))
          }
          elements = XPath.match(element, "ds:DigestMethod", {"ds" => Namespaces::DS})
          #element.each_element("ds:DigestMethod"){|e|
          elements.each{|e|
            @digest_algorithm = e.attribute("Algorithm")
          }
          elements = XPath.match(element, "ds:DigestValue", {"ds" => Namespaces::DS})
          #element.each_element("ds:DigestValue"){|e|
          elements.each{|e|
            @digest_value = e.text().strip()
          }
          @ref_element = XPath.first(element.document, "//*[@wsu:Id='"+@uri+"']")
	end	
	
	def verify()
          trans_element = nil
          @transforms.each{|transform_algorithm|
            transformer = TransformerFactory::get_instance(transform_algorithm)
            transformer.prefix_list=(@prefix_list)
            trans_element = transformer.canonicalize_element(@ref_element)
          }
          if (@transforms.size() == 0)
            transformer = TransformerFactory::get_instance("http://www.w3.org/2001/10/xml-exc-c14n#")
            transformer.prefix_list=(@prefix_list)
            trans_element = transformer.canonicalize_element(@ref_element)
          end
          digester = DigestFactory::get_instance(@digest_algorithm.value())
          digest = digester.digest_b64(trans_element)
          return true if (digest == @digest_value)
          false
	end
      end

    end
  end
end