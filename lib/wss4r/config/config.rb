require "yaml"
require "date"


module WSS4R
   module Config
      class Config
         attr_accessor :encrypt_certificate, :signature_certificate, :resolver
         
         def initialize()
            @encrypt_certificate = "certificate_by_subject,/C=DE/ST=Rheinland-Pfalz/L=Trier/O=FF/OU=Development/CN=Server/emailAddress=server@web.de"
            @signature_certificate = "certificate_by_subject,/C=DE/ST=Rheinland-Pfalz/L=Trier/O=FF/OU=Developement/CN=Client/emailAddress=client@web.de"
            @resolver = "CertificateDirectoryResolver, ../../certs/ca/"
         end
         
         def build_security(security)
            resolver = create_instance(@resolver)	
            cert = create_call(resolver, @signature_certificate)
            security.add_security_resolver(resolver)
            security
         end
         
=begin		
		cert = Certificate.new(File.new(@encrypt_certificate))
		x509 = X509SecurityToken.new(cert)
		enc_data = EncryptedData.new(x509)
		
		sign_cert = @resolver.certificate_by_subject(SUBJECT_SERVER)
		pkey = @resolver.private_key(sign_cert)
		x509 = X509SecurityToken.new(sign_cert, pkey)
		signature = Signature.new(x509)

		
		@driver.get_security().add_security_token(enc_data)
=end		
         
         def create_instance(desc)
            args = desc.split(",")
            klass = args.shift().strip()
            instance = klass+".new('" + args.shift().strip!()+"'" if (args.size() > 0)
            
            args.each {|e|
               instance = instance + ",'" + e.strip!() + "'"
            }
            instance = instance + ")"
            obj = eval(instance)
            obj
         end
         
         def create_call(obj, desc)
            args = desc.split(",")
            name = args.shift().strip()
            meth = obj.method(name)
            parameters = ""
            parameters = args.shift().strip() if (args.size() > 0)
            
            args.each {|a|
               parameters = parameters + "," + a.to_s()
            }
            return_value = meth.call(parameters)
            return_value
         end	
      end
      
      class Store
         def initialize(file=".\\wss4r-conf.yaml")
            @file = file
         end
         
         def save(config)
            file = File.new(@file,"w")
            YAML::dump(config, file)
            file.close()
         end
         
         def load()
            begin
               file = File.open(@file)
               config = YAML::load(file.read())
            rescue Exception
               return nil
            end
            config
         end
      end
      
      
   end #Config
end #WSS4R


if __FILE__ == $0
	require "wss4r/rpc/wssdriver"
	require "wss4r/security/security"
	require "wss4r/tokenresolver/certificateresolver"
	include WSS4R::Tokenresolver
	
   config = WSS4R::Config::Config.new()
   config.build_security(nil)
   
   store  = WSS4R::Config::Store.new()
   store.save(config)
   config = store.load()
   puts(config)
end
