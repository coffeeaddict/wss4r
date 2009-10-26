require File.dirname(__FILE__) + '/../test_helper'
require 'certificate_service_controller'

class CertificateServiceController; def rescue_action(e) raise e end; end

class CertificateServiceControllerApiTest < Test::Unit::TestCase
  def setup
    @controller = CertificateServiceController.new
    @request    = ActionController::TestRequest.new
    @response   = ActionController::TestResponse.new
  end

  def test_find_certificate
    result = invoke :find_certificate
    assert_equal nil, result
  end
end
