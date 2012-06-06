/*
 * @author: ucla-cs
 * This class represents SignedInfo Object
 * This keeps information about the ContentObject Signature
 */

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

SignedInfo.prototype.setFields = function(){
	//BASE64 -> RAW STRING
	
	//this.Locator = new KeyLocator(  DataUtils.toNumbersFromString(stringCertificate)  ,KeyLocatorType.CERTIFICATE );
	
	var publicKeyHex = globalKeyManager.publicKey;

	console.log('PUBLIC KEY TO WRITE TO CONTENT OBJECT IS ');
	console.log(publicKeyHex);
	
	var publicKeyBytes = DataUtils.toNumbers(globalKeyManager.publicKey) ; 

	

	//var stringCertificate = DataUtils.base64toString(globalKeyManager.certificate);
	
	//if(LOG>3)console.log('string Certificate is '+stringCertificate);

	//HEX -> BYTE ARRAY
	//var publisherkey = DataUtils.toNumbers(hex_sha256(stringCertificate));
	
	//if(LOG>3)console.log('publisher key is ');
	//if(LOG>3)console.log(publisherkey);
	
	var publisherKeyDigest = hex_sha256_from_bytes(publicKeyBytes);

	this.Publisher = new PublisherPublicKeyDigest(  DataUtils.toNumbers(  publisherKeyDigest )  );
	
	//this.Publisher = new PublisherPublicKeyDigest(publisherkey);

	var d = new Date();
	
	var time = d.getTime();
	

    this.Timestamp = new CCNTime( time );
    
    if(LOG>4)console.log('TIME msec is');

    if(LOG>4)console.log(this.Timestamp.msec);

    //DATA
	this.Type = 0;//0x0C04C0;//ContentTypeValue[ContentType.DATA];
	
	//if(LOG>4)console.log('toNumbersFromString(stringCertificate) '+DataUtils.toNumbersFromString(stringCertificate));
	
	console.log('PUBLIC KEY TO WRITE TO CONTENT OBJECT IS ');
	console.log(publicKeyBytes);

	this.Locator = new KeyLocator(  publicKeyBytes  ,KeyLocatorType.KEY );

	//this.Locator = new KeyLocator(  DataUtils.toNumbersFromString(stringCertificate)  ,KeyLocatorType.CERTIFICATE );

};

SignedInfo.prototype.decode = function( decoder){

		decoder.readStartElement( this.getElementLabel() );
		
		if (decoder.peekStartElement(CCNProtocolDTags.PublisherPublicKeyDigest)) {
			if(LOG>3) console.log('DECODING PUBLISHER KEY');
			this.Publisher = new PublisherPublicKeyDigest();
			this.Publisher.decode(decoder);
		}

		if (decoder.peekStartElement(CCNProtocolDTags.Timestamp)) {
			this.Timestamp = decoder.readDateTime(CCNProtocolDTags.Timestamp);
			if(LOG>4)console.log('TIMESTAMP FOUND IS  '+this.Timestamp);

		}

		if (decoder.peekStartElement(CCNProtocolDTags.Type)) {
			binType = decoder.readBinaryElement(CCNProtocolDTags.Type);//byte [] 
		
			
			//TODO Implement Type of Key Reading
			
			if(LOG>4)console.log('Binary Type of of Signed Info is '+binType);

			this.Type = binType;
			
			
			//TODO Implement Type of Key Reading
			
			
			if (null == this.Type) {
				throw new Exception("Cannot parse signedInfo type: bytes.");
			}
			
		} else {
			this.Type = ContentType.DATA; // default
		}
		
		if (decoder.peekStartElement(CCNProtocolDTags.FreshnessSeconds)) {
			this.FreshnessSeconds = decoder.readIntegerElement(CCNProtocolDTags.FreshnessSeconds);
			if(LOG>4) console.log('FRESHNESS IN SECONDS IS '+ this.FreshnessSeconds);
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
			if(LOG>3) console.log('ENCODING PUBLISHER KEY' + this.Publisher.PublisherPublicKeyDigest);

			this.Publisher.encode(encoder);
		}

		if (null!=this.Timestamp) {
			encoder.writeDateTime(CCNProtocolDTags.Timestamp, this.Timestamp );
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
	
SignedInfo.prototype.valueToType = function(){
	//for (Entry<byte [], ContentType> entry : ContentValueTypes.entrySet()) {
		//if (Arrays.equals(value, entry.getKey()))
			//return entry.getValue();
		//}
	return null;
	
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

