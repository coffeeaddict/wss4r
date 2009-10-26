module WSS4R
module Security
module Xml

class ReferenceList
	attr_reader :uris
	
   def initialize(referencelist)
      @uris = parse_reference_list(referencelist)
   end
   
   def parse_reference_list(list)
      @uris = Array.new()
      elements = list.get_elements("//" + Names::DATA_REFERENCE)
      elements.each{|e|
         @uris.push(e.attribute("URI").value())
      }
      @uris
   end
end

end #Xml
end #Security
end #WSS4R