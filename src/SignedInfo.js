var CCNProtocolDTags = require('./CCNProtocolDTags').CCNProtocolDTags;

var SignedInfo = function SignedInfo(_publisher,_timestamp,_type,_locator,_freshnessSeconds,_finalBlockID){

	//TODO, Check types
    
    this.Publisher = _publisher; //PublisherPublicKeyDigest
    this.Timestamp=_timestamp; // CCN Time
    this.Type=_type; // ContentType
    this.Locator =_locator;//KeyLocator
    this.FreshnessSeconds =_freshnessSeconds; // Integer
    this.FinalBlockID=_finalBlockID; //byte array

};

//exports.SignedInfo.Working;


SignedInfo.prototype.decode = function( decoder){

		decoder.readStartElement( this.getElementLabel() );
		
		if (decoder.peekStartElement(CCNProtocolDTags.PublisherPublicKeyDigest)) {
			this.Publisher = new PublisherPublicKeyDigest();
			this.Publisher.decode(decoder);
		}

		if (decoder.peekStartElement(CCNProtocolDTags.Timestamp)) {
			this.Timestamp = decoder.readDateTime(CCNProtocolDTags.Timestamp);
		}

		if (decoder.peekStartElement(CCNProtocolDTags.Type)) {
			binType = decoder.readBinaryElement(CCNProtocolDTags.Type);//byte [] 
			//TODO Implement valueToType
			
			this.Type = valueToType(binType);
			if (null == this.Type) {
				throw new Exception("Cannot parse signedInfo type: bytes.");
			}
			
		} else {
			this.Type = ContentType.DATA; // default
		}
		
		if (decoder.peekStartElement(CCNProtocolDTags.FreshnessSeconds)) {
			this.FreshnessSeconds = decoder.readIntegerElement(CCNProtocolDTags.FreshnessSeconds);
		}
		
		if (decoder.peekStartElement(CCNProtocolDTags.FinalBlockID)) {
			this.FinalBlockID = decoder.readBinaryElement(CCNProtocolDTags.FinalBlockID);
		}
		
		if (decoder.peekStartElement(CCNProtocolDTags.KeyLocator)) {
			this.Locator = new KeyLocator();
			this.Locator.decode(decoder);
		}
				
		decoder.readEndElement();
};

SignedInfo.prototype.encode = function( encoder)  {
		if (!this.validate()) {
			throw new Exception("Cannot encode : field values missing.");
		}
		encoder.writeStartElement(this.getElementLabel());
		
		if (null!=this.Publisher) {
			this.Publisher.encode(encoder);
		}

		if (null!=this.Timestamp) {
			encoder.writeDateTime(CCNProtocolDTags.Timestamp, this.Timestamp);
		}
		
		if (null!=this.Type) {
			
			encoder.writeElement(CCNProtocolDTags.Type, this.Type);
		}
		
		if (null!=this.FreshnessSeconds) {
			encoder.writeElement(CCNProtocolDTags.FreshnessSeconds, this.FreshnessSeconds);
		}

		if (null!=this.FinalBlockID) {
			encoder.writeElement(CCNProtocolDTags.FinalBlockID, this.FinalBlockID);
		}

		if (null!=this.Locator) {
			this.Locator.encode(encoder);
		}

		encoder.writeEndElement();   		
};
	
SignedInfo.prototype.getElementLabel = function() { 
	return CCNProtocolDTags.SignedInfo;
};

SignedInfo.prototype.validate = function() {
		// We don't do partial matches any more, even though encoder/decoder
		// is still pretty generous.
		if (null ==this.Publisher || null==this.Timestamp ||null== this.Locator)
			return false;
		return true;
	};

