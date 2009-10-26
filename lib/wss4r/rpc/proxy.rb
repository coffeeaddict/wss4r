class SOAP::RPC::Proxy
  def security()
    if (@security == nil)
      @security = WSS4R::Security::Security.new()
      return @security
    end
    @security
  end
      
  def create_encoding_opt(hash = nil)
    opt = {}
    opt[:security] = @security
    opt[:default_encodingstyle] = @default_encodingstyle
    opt[:allow_unqualified_element] = @allow_unqualified_element
    opt[:generate_explicit_type] = @generate_explicit_type
    opt[:no_indent] = @options["soap.envelope.no_indent"]
    opt.update(hash) if hash
    opt
  end
  
  def invoke(req_header, req_body, opt = nil)
    opt ||= create_options
    opt[:security] = @security
    route(req_header, req_body, opt, opt)
  end  
end
