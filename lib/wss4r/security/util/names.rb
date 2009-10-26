module WSS4R
module Security
module Util

class Names
	HEADER = "env:Header"
	SECURITY = "wsse:Security"
	BODY = "env:Body"
	ENCRYPTED_DATA = "xenc:EncryptedData"
	ENCRYPTION_METHOD = "xenc:EncryptionMethod"
	CIPHER_DATA = "xenc:CipherData"
	CIPHER_VALUE = "xenc:CipherValue"
	ENCRYPTED_KEY = "xenc:EncryptedKey"
	KEY_INFO = "ds:KeyInfo"
	SECURITY_TOKEN_REFERENCE = "wsse:SecurityTokenReference"
	KEY_IDENTIFIER = "wsse:KeyIdentifier"
	REFERENCE_LIST = "xenc:ReferenceList"
	DATA_REFERENCE = "xenc:DataReference"
	REFERENCE_WSSE = "wsse:Reference"
	REFERENCE_DS = "ds:Reference"
	SIGNATURE_VALUE = "ds:SignatureValue"
	SIGNATURE = "ds:Signature"
	CANONICALIZATION_METHOD = "ds:CanonicalizationMethod"
	SIGNATURE_METHOD = "ds:SignatureMethod"
	TRANSFORMS = "ds:Transforms"
	TRANSFORM = "ds:Transform"
	DIGEST_METHOD = "ds:DigestMethod"
	DIGEST_VALUE = "ds:DigestValue"
	BINARY_SECURITY_TOKEN = "wsse:BinarySecurityToken"
	SIGNED_INFO="ds:SignedInfo"
	TIMESTAMP = "wsu:Timestamp"
	CREATED = "wsu:Created"
	EXPIRES = "wsu:Expires"
end

end #Util
end #Security
end #WSS4R