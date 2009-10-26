class SOAP::RPC::Router
  def unmarshal(conn_data)
    opt = {}
    opt[:security] = @security
    contenttype = conn_data.receive_contenttype
    if /#{MIMEMessage::MultipartContentType}/i =~ contenttype
      opt[:external_content] = {}
      mime = MIMEMessage.parse("Content-Type: " + contenttype, conn_data.receive_string)
      mime.parts.each do |part|
        value = Attachment.new(part.content)
        value.contentid = part.contentid
        obj = SOAPAttachment.new(value)
        opt[:external_content][value.contentid] = obj if value.contentid
      end
      opt[:charset] =  StreamHandler.parse_media_type(mime.root.headers['content-type'].str)
      env = Processor.unmarshal(mime.root.content, opt)
    else
      opt[:charset] = ::SOAP::StreamHandler.parse_media_type(contenttype)
      env = Processor.unmarshal(conn_data.receive_string, opt)
    end
    charset = opt[:charset]
    conn_data.send_contenttype = "text/xml; charset=\"#{charset}\""
    env
  end

  def marshal(conn_data, env, default_encodingstyle = nil)
    opt = {}
    opt[:security] = @security
    opt[:external_content] = nil
    opt[:default_encodingstyle] = default_encodingstyle
    opt[:generate_explicit_type] = @generate_explicit_type
    response_string = Processor.marshal(env, opt)
    conn_data.send_string = response_string
    if ext = opt[:external_content]
      mimeize(conn_data, ext)
    end
    conn_data
  end
					
  def security()
    if (@security == nil)
      @security = Security.new()
    end
    @security
  end 
end
