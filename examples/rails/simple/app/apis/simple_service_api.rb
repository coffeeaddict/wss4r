class SimpleServiceApi < ActionWebService::API::Base
	inflect_names false
	api_method :test, :expects => [:string], :returns => [:string]
end
