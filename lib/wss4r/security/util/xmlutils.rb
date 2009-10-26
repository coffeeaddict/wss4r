require "rexml/document"

include REXML

class REXML::Element
	def index_of(e)
		return -1 if (e == nil)
		children = self.children()
		children.each_with_index {|child, i|
			return i if (child.local_name() == e.local_name())
		}
		return -1
	end
end

class REXML::Document
	def select(xpath)
		#XPath.first(document, "/env:Envelope/env:Header/wsse:Security/ds:Signature")
		element = XPath.first(self, xpath)
		if (element != nil)
			return element
		end
		node_path = xpath.sub("/","").split("/")
		
		element = self
		
		node_path.each{|expr|
			element = select_element(element, expr)
			if (element == nil)
				return nil
			end
		}
		element
	end
	
	def select_element(element, name)
		childs = Array.new()
		element.each_child{|child|
			if (child.node_type() == :element)
				if (child.expanded_name() == name)
					childs.push(child)
					return child
				end
			end
		}
		nil
	end
	
	def element_with_attribute(key, value)

	end
end

if __FILE__ == $0
	document = REXML::Document.new(File.new(ARGV[0]))
	element = document.select("/env:Envelope/env:Header/wsse:Security/ds:Signature")
	puts("selected: " + element.to_s())
end