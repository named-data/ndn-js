/*
 * @author: ucla-cs
 * This class represents KeyLocator Objects
 */

var KeyLocatorType = {
	  NAME:1,
	  KEY:2,
	  CERTIFICATE:3
};

var KeyLocator = function KeyLocator(_Input,_Type){ 

    this.Type=_Type;
    
    if (_Type==KeyLocatorType.NAME){
    	this.KeyName = _Input;
    }
    else if(_Type==KeyLocatorType.KEY){
    	console.log('SET KEY');
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
				
				//TODO FIX THIS, This should create a Key Object instead of keeping bytes

				this.PublicKey =   encodedKey;//CryptoUtil.getPublicKey(encodedKey);
				this.Type = 2;
				

				if(LOG>4) console.log('PUBLIC KEY FOUND: '+ this.PublicKey);
				//this.PublicKey = encodedKey;
				
				
			} catch (e) {
				throw new Exception("Cannot parse key: ", e);
			} 

			if (null == this.PublicKey) {
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
				

				this.Certificate = encodedCert;
				this.Type = 3;

				if(LOG>4) console.log('CERTIFICATE FOUND: '+ this.Certificate);
				
			} catch ( e) {
				throw new Exception("Cannot decode certificate: " +  e);
			}
			if (null == this.Certificate) {
				throw new Exception("Cannot parse certificate! ");
			}
		} else  {
			this.Type = 1;


			this.KeyName = new KeyName();
			this.KeyName.decode(decoder);
		}
		decoder.readEndElement();
	}
	

	KeyLocator.prototype.encode = function( encoder) {
		
		if(LOG>2) console.log('type is is ' + this.Type);
		//TODO Check if Name is missing
		if (!this.validate()) {
			throw new ContentEncodingException("Cannot encode " + this.getClass().getName() + ": field values missing.");
		}

		
		//TODO FIX THIS TOO
		encoder.writeStartElement(this.getElementLabel());
		
		if (this.Type == KeyLocatorType.KEY) {
			if(LOG>5)console.log('About to encode a public key' +this.PublicKey);
			encoder.writeElement(CCNProtocolDTags.Key, this.PublicKey);
			
		} else if (this.Type == KeyLocatorType.CERTIFICATE) {
			
			try {
				encoder.writeElement(CCNProtocolDTags.Certificate, this.Certificate);
			} catch ( e) {
				throw new Exception("CertificateEncodingException attempting to write key locator: " + e);
			}
			
		} else if (this.Type == KeyLocatorType.NAME) {
			
			this.KeyName.encode(encoder);
		}
		encoder.writeEndElement();
		
};

KeyLocator.prototype.getElementLabel = function() {
	return CCNProtocolDTags.KeyLocator; 
};

KeyLocator.prototype.validate = function() {
	return (  (null != this.KeyName) || (null != this.PublicKey) || (null != this.Certificate)   );
};
	