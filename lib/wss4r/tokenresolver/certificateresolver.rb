require "wss4r/tokenresolver/resolver.rb"
require "wss4r/security/crypto/certificate"

module WSS4R
  module Tokenresolver
    class CertificateDirectoryResolver < Resolver
		
      def initialize(directory)
        File.stat(directory).directory?
        @directory = directory
      end
		
      def certificate_by_key_identifier(key_identifier)
        files = Dir[@directory + "/*.cer"]
        files.each{|f|
          certificate = Certificate.new(File.read(f))
          if (key_identifier == certificate.key_identifier())
            certificate.filename=(f)
            return certificate
          end
        }
        nil
      end
		
      def private_key(certificate, passphrase=nil)
        if (certificate.filename() != nil)
          if passphrase
            return (RSA.new(File.read(certificate.filename()), passphrase))
          else
            return (RSA.new(File.read(certificate.filename() + ".key")))
          end
        end
        files = Dir[@directory + "/*.key"]
        files.each{|f|
          pkey = RSA.new(File.read(f))
          if (certificate.check_private_key(pkey))
            return pkey
          end
        }
        return nil
      end
		
      def certificate_by_subject(subject)
        files = Dir[@directory + "/*.cer"]
        files.each{|f|
          certificate = Certificate.new(File.read(f))
          if (certificate.subject().to_s() == subject)
            certificate.filename=(f)
            return certificate
          end
        }
        nil
      end
    end
  end
end


#c = WSS4R::Tokenresolver::CertificateDirectoryResolver.new("./certs")
#cert = c.get_certificate_by_key_identifier("tUYo1KhZtRDiUf1LVNDUopTczmo=")
#key = c.get_private_key(cert)
#puts(key.to_s())
