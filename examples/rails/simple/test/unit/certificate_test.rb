require File.dirname(__FILE__) + '/../test_helper'

class CertificateTest < Test::Unit::TestCase
  fixtures :certificates

  def setup
    @certificate = Certificate.find(1)
  end

  # Replace this with your real tests.
  def test_truth
    assert_kind_of Certificate,  @certificate
  end
end
