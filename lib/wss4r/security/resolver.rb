class Resolver < Array
  def authenticate_user(usernametoken)
    self.each{|r|
      success = r.authenticate_user(usernametoken)
      return true if (success)
    }
    false
  end
  def private_key(certificate)
    self.each{|r|
      key = r.private_key(certificate)
      return key if (key)
    }
    nil
  end
  def certificate_by_subject(subject)
    self.each{|r|
      certificate = r.certificate_by_subject(subject)
      return certificate if (certificate)
    }
    nil
  end
end
