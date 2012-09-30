/*
 * @author: ucla-cs
 * This class represents Publisher and PublisherType Objects
 */


var PublisherType = function PublisherType(_tag){
    	this.KEY =(CCNProtocolDTags.PublisherPublicKeyDigest);
    	this.CERTIFICATE= (CCNProtocolDTags.PublisherCertificateDigest);
    	this.ISSUER_KEY=	(CCNProtocolDTags.PublisherIssuerKeyDigest);
    	this.ISSUER_CERTIFICATE	=(CCNProtocolDTags.PublisherIssuerCertificateDigest);

    	this.Tag = _tag;
}; 

var isTypeTagVal = function(tagVal) {
		if ((tagVal == CCNProtocolDTags.PublisherPublicKeyDigest) ||
			(tagVal == CCNProtocolDTags.PublisherCertificateDigest) ||
			(tagVal == CCNProtocolDTags.PublisherIssuerKeyDigest) ||
			(tagVal == CCNProtocolDTags.PublisherIssuerCertificateDigest)) {
			return true;
		}
		return false;
};




var PublisherID = function PublisherID() {

	this.PUBLISHER_ID_DIGEST_ALGORITHM = "SHA-256";
	this.PUBLISHER_ID_LEN = 256/8;
    
	//TODO, implement publisherID creation and key creation

    //TODO implement generatePublicKeyDigest
    this.PublisherID =null;//= generatePublicKeyDigest(key);//ByteArray
    
    //TODO implement generate key
    //CryptoUtil.generateKeyID(PUBLISHER_ID_DIGEST_ALGORITHM, key);
    this.PublisherType = null;//isIssuer ? PublisherType.ISSUER_KEY : PublisherType.KEY;//publisher Type
    
};


PublisherID.prototype.decode = function(decoder) {
		
		// We have a choice here of one of 4 binary element types.
		var nextTag = decoder.peekStartElementAsLong();
		
		if (null == nextTag) {
			throw new Exception("Cannot parse publisher ID.");
		} 
		
		this.PublisherType = new PublisherType(nextTag); 
		
		if (!isTypeTagVal(nextTag)) {
			throw new Exception("Invalid publisher ID, got unexpected type: " + nextTag);
		}
		this.PublisherID = decoder.readBinaryElement(nextTag);
		if (null == this.PublisherID) {
			throw new ContentDecodingException("Cannot parse publisher ID of type : " + nextTag + ".");
		}
};

PublisherID.prototype.encode = function(encoder) {
	if (!this.validate()) {
		throw new Exception("Cannot encode " + this.getClass().getName() + ": field values missing.");
	}

	encoder.writeElement(this.getElementLabel(), this.PublisherID);
};
	
PublisherID.peek = function(/* XMLDecoder */ decoder) {

		//Long
		nextTag = decoder.peekStartElementAsLong();
		
		if (null == nextTag) {
			// on end element
			return false;
		}
		return (isTypeTagVal(nextTag));
	};

PublisherID.prototype.getElementLabel = function() { 
	return this.PublisherType.Tag;
};

PublisherID.prototype.validate = function(){
	return ((null != id() && (null != type())));
};



