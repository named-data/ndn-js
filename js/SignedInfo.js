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

    this.publisher = _publisher; //publisherPublicKeyDigest
    this.timestamp=_timestamp; // CCN Time
    this.type=_type; // ContentType
    this.locator =_locator;//KeyLocator
    this.freshnessSeconds =_freshnessSeconds; // Integer
    this.finalBlockID=_finalBlockID; //byte array

};

SignedInfo.prototype.setFields = function(){
	//BASE64 -> RAW STRING
	
	//this.locator = new KeyLocator(  DataUtils.toNumbersFromString(stringCertificate)  ,KeyLocatorType.CERTIFICATE );
	
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

	this.publisher = new PublisherPublicKeyDigest(  DataUtils.toNumbers(  publisherKeyDigest )  );
	
	//this.publisher = new PublisherPublicKeyDigest(publisherkey);

	var d = new Date();
	
	var time = d.getTime();
	

    this.timestamp = new CCNTime( time );
    
    if(LOG>4)console.log('TIME msec is');

    if(LOG>4)console.log(this.timestamp.msec);

    //DATA
	this.type = 0;//0x0C04C0;//ContentTypeValue[ContentType.DATA];
	
	//if(LOG>4)console.log('toNumbersFromString(stringCertificate) '+DataUtils.toNumbersFromString(stringCertificate));
	
	console.log('PUBLIC KEY TO WRITE TO CONTENT OBJECT IS ');
	console.log(publicKeyBytes);

	this.locator = new KeyLocator(  publicKeyBytes  ,KeyLocatorType.KEY );

	//this.locator = new KeyLocator(  DataUtils.toNumbersFromString(stringCertificate)  ,KeyLocatorType.CERTIFICATE );

};

SignedInfo.prototype.from_ccnb = function( decoder){

		decoder.readStartElement( this.getElementLabel() );
		
		if (decoder.peekStartElement(CCNProtocolDTags.PublisherPublicKeyDigest)) {
			if(LOG>3) console.log('DECODING PUBLISHER KEY');
			this.publisher = new PublisherPublicKeyDigest();
			this.publisher.from_ccnb(decoder);
		}

		if (decoder.peekStartElement(CCNProtocolDTags.Timestamp)) {
			this.timestamp = decoder.readDateTime(CCNProtocolDTags.Timestamp);
			if(LOG>4)console.log('TIMESTAMP FOUND IS  '+this.timestamp);

		}

		if (decoder.peekStartElement(CCNProtocolDTags.Type)) {
			binType = decoder.readBinaryElement(CCNProtocolDTags.Type);//byte [] 
		
			
			//TODO Implement type of Key Reading
			
			if(LOG>4)console.log('Binary Type of of Signed Info is '+binType);

			this.type = binType;
			
			
			//TODO Implement type of Key Reading
			
			
			if (null == this.type) {
				throw new Error("Cannot parse signedInfo type: bytes.");
			}
			
		} else {
			this.type = ContentType.DATA; // default
		}
		
		if (decoder.peekStartElement(CCNProtocolDTags.FreshnessSeconds)) {
			this.freshnessSeconds = decoder.readIntegerElement(CCNProtocolDTags.FreshnessSeconds);
			if(LOG>4) console.log('FRESHNESS IN SECONDS IS '+ this.freshnessSeconds);
		}
		
		if (decoder.peekStartElement(CCNProtocolDTags.FinalBlockID)) {
			this.finalBlockID = decoder.readBinaryElement(CCNProtocolDTags.FinalBlockID);
		}
		
		if (decoder.peekStartElement(CCNProtocolDTags.KeyLocator)) {
			this.locator = new KeyLocator();
			this.locator.from_ccnb(decoder);
		}
				
		decoder.readEndElement();
};

SignedInfo.prototype.to_ccnb = function( encoder)  {
		if (!this.validate()) {
			throw new Error("Cannot encode : field values missing.");
		}
		encoder.writeStartElement(this.getElementLabel());
		
		if (null!=this.publisher) {
			if(LOG>3) console.log('ENCODING PUBLISHER KEY' + this.publisher.publisherPublicKeyDigest);

			this.publisher.to_ccnb(encoder);
		}

		if (null!=this.timestamp) {
			encoder.writeDateTime(CCNProtocolDTags.Timestamp, this.timestamp );
		}
		
		if (null!=this.type && this.type !=0) {
			
			encoder.writeElement(CCNProtocolDTags.type, this.type);
		}
		
		if (null!=this.freshnessSeconds) {
			encoder.writeElement(CCNProtocolDTags.FreshnessSeconds, this.freshnessSeconds);
		}

		if (null!=this.finalBlockID) {
			encoder.writeElement(CCNProtocolDTags.FinalBlockID, this.finalBlockID);
		}

		if (null!=this.locator) {
			this.locator.to_ccnb(encoder);
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
		if (null ==this.publisher || null==this.timestamp ||null== this.locator)
			return false;
		return true;
};

