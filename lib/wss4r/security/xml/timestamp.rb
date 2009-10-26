module WSS4R
  module Security
    module Xml

      class Timestamp
	
	def process(security)
          timestamp = security.add_element(Names::TIMESTAMP)
          timestamp.add_attribute("wsu:Id", timestamp.object_id().to_s())
          created = timestamp.add_element(Names::CREATED)
          expires = timestamp.add_element(Names::EXPIRES)

		
          #BUG #4400-------------------------------
          #created_time = Time.new().gmtime()
          #expired_time = created_time+5*60 #
          created_time = Time.new().getutc()
          expired_time = created_time+(60*5)
		
          created_time = created_time.iso8601()
          expired_time = expired_time.iso8601()

          created.text=(created_time.to_s())
          expires.text=(expired_time.to_s())
          security
	end
	
	def unprocess(timestamp)
          created = XPath.first(timestamp, "wsu:Created", {"wsu"=>Namespaces::WSU}).text()
          expires = XPath.first(timestamp, "wsu:Expires", {"wsu"=>Namespaces::WSU}).text()
          created_parms = ParseDate::parsedate(created)
          expires_parms = ParseDate::parsedate(expires)
          @created_time = Time.gm(created_parms[0], created_parms[1],created_parms[2],created_parms[3], created_parms[4], created_parms[5])
          @expires_time = Time.gm(expires_parms[0], expires_parms[1],expires_parms[2],expires_parms[3], expires_parms[4], expires_parms[5])
	end
	
	def verify()
          time = Time.new().gmtime()
          if !(@created_time <= time && time <= @expires_time)
            raise WSS4R::Security::Exceptions::TimestampFault.new()
          end
	end
      end

    end #Xml
  end #Security
end #WSS4R
