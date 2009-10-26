require "rexml/document"
require "breakpoint"

include REXML

class REXML::Element
	def index_of(e)
		children = self.children()
		children.each_with_index {|child, i|
			return i if (child.local_name() == e.local_name())
		}
		return -1
	end
end

doc = Document.new()
root = doc.add_element("root")
eins = root.add_element("eins")
zwei = root.add_element("zwei")
drei = root.add_element("drei")
drei_eins = drei.add_element("drei-eins")
drei_zwei = drei.add_element("drei-zwei")
drei_drei = drei.add_element("drei-drei")



e = XPath.first(root, "zwei")
breakpoint
