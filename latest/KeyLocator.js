




var KeyLocatorType = {
	  NAME:1,
	  KEY:2,
	  CERTIFICATE:3
};

var KeyLocator = function KeyLocator(_Input,_Type){ 

    //this.KeyName = _KeyName;
    //this.PublicKey = _PublicKey;
    //this.Certificate =  _Certificate;
    
    this.Type=_Type;
    
    if (_Type==KeyLocatorType.NAME){
    	this.KeyName = _Input;
    }
    else if(_Type==KeyLocatorType.KEY){
    	this.PublicKey = _Input;
    }
    else if(_Type==KeyLocatorType.CERTIFICATE){
    	this.Certificate = _Input;
    }
    
};

KeyLocator.prototype.decode = function(decoder) {

		decoder.readStartElement(this.getElementLabel());

		if (decoder.peekStartElement(CCNProtocolDTags.Key)) {
			try {
				encodedKey = decoder.readBinaryElement(CCNProtocolDTags.Key);
				// This is a DER-encoded SubjectPublicKeyInfo.
				
				//TODO FIX THIS, SHOULDN'T be like that
				this.Key =   encodedKey;//CryptoUtil.getPublicKey(encodedKey);
				
				this.PublicKey = encodedKey;
				
				
			} catch (e) {
				console.log("Cannot parse stored key: error: " + e);
				throw new ContentDecodingException("Cannot parse key: ", e);
			} 

			if (null == this.Key) {
				throw new Exception("Cannot parse key: ");
			}

		} else if ( decoder.peekStartElement(CCNProtocolDTags.Certificate)) {
			try {
				encodedCert = decoder.readBinaryElement(CCNProtocolDTags.Certificate);
				
				/*
				 * Certificates not yet working
				 */
				
				//CertificateFactory factory = CertificateFactory.getInstance("X.509");
				//this.Certificate = (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(encodedCert));
				
			} catch ( e) {
				throw new Exception("Cannot decode certificate: " +  e);
			}
			if (null == this.Certificate) {
				throw new Exception("Cannot parse certificate! ");
			}
		} else {
			this.KeyName = new KeyName();
			this.KeyName.decode(decoder);
		}
		decoder.readEndElement();
		}
	

		KeyLocator.prototype.encode = function( encoder) {
		/*if (!validate()) {
			throw new ContentEncodingException("Cannot encode " + this.getClass().getName() + ": field values missing.");
		}*/

		
		//TODO FIX THIS TOO
		encoder.writeStartElement(this.getElementLabel());
		
		if (this._Type == KeyLocatorType.KEY) {
			console.log('HERE');
			
			encoder.writeElement(CCNProtocolDTags.Key, this.PublicKey);
			
		} else if (this.Type == KeyLocatorType.CERTIFICATE) {
			console.log('NO HERE');
			
			try {
				encoder.writeElement(CCNProtocolDTags.Certificate, this.Certificate.getEncoded());
			} catch ( e) {
				throw new Exception("CertificateEncodingException attempting to write key locator: " + e);
			}
			
		} else if (this.Type == KeyLocatorType.NAME) {
			console.log('ACTUALLY HERE');
			this.KeyName.encode(encoder);
		}
		encoder.writeEndElement();
		
};
	
KeyLocator.prototype.getElementLabel = function() {
	return CCNProtocolDTags.KeyLocator; 
};

KeyLocator.prototype.validate = function() {
	return (  (null != this.keyName) || (null != this.PublicKey) || (null != this.Certificate)   );
};
	