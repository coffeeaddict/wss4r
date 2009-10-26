module WSS4R
  module Security
    module Util

      module Types
        VALUE_BASE64BINARY = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3"
        VALUE_KEYIDENTIFIER = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509SubjectKeyIdentifier"
        REFERENCE_VALUETYPE_X509 = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3"
	ENCODING_X509V3="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary"
        ENCRYPTEDKEY = "http://www.w3.org/2001/04/xmlenc#EncryptedKey"
        ALGORITHM_RSA15 = "http://www.w3.org/2001/04/xmlenc#rsa-1_5"
        XENC_CONTENT = "http://www.w3.org/2001/04/xmlenc#Content"
        ALGORITHM_3DES_CBC = "http://www.w3.org/2001/04/xmlenc#tripledes-cbc"
	ALGORITHM_AES_CBC = "http://www.w3.org/2001/04/xmlenc#aes256-cbc"
        ALGORITHM_AES128_CBC = "http://www.w3.org/2001/04/xmlenc#aes128-cbc"
	CANON_C14N_EXCL = "http://www.w3.org/2001/10/xml-exc-c14n#"
	SIG_ALG_RSA_SHA1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
	DIG_METHOD_SHA1 = "http://www.w3.org/2000/09/xmldsig#sha1"
	PASSWORD_DIGEST = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest"
	PASSWORD_TEXT = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText"
      end

    end #Util
  end #Security
end #WSS4R
