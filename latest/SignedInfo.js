
var ContentType = {DATA:0, ENCR:1, GONE:2, KEY:3, LINK:4, NACK:5};

var ContentTypeValue = {0:0x0C04C0, 1:0x10D091,2:0x18E344,3:0x28463F,4:0x2C834A,5:0x34008A};
var ContentTypeValueReverse = {0x0C04C0:0, 0x10D091:1,0x18E344:2,0x28463F:3,0x2C834A:4,0x34008A:5};


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
			//console.log('GOT HERRRRRRRRRRRRRRRRRE');
			//console.log(binType);
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
		
		if (null!=this.Type && this.Type !=0) {
			
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

