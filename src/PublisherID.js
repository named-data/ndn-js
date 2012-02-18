var CCNProtocolDTags = require('./CCNProtocolDTags').CCNProtocolDTags;


var PublisherType = function PublisherType(_tag){
    	this.KEY =(CCNProtocolDTags.PublisherPublicKeyDigest);
    	this.CERTIFICATE= (CCNProtocolDTags.PublisherCertificateDigest);
    	this.ISSUER_KEY=	(CCNProtocolDTags.PublisherIssuerKeyDigest);
    	this.ISSUER_CERTIFICATE	=(CCNProtocolDTags.PublisherIssuerCertificateDigest);

    	this.Tag = _tag;
}; exports.PublisherType = PublisherType;

PublisherType.prototype.isTypeTagVal = function(tagVal) {
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
    
    
    this.PublisherID = generatePublicKeyDigest(key);//ByteArray
    //CryptoUtil.generateKeyID(PUBLISHER_ID_DIGEST_ALGORITHM, key);
    this.PublisherType = isIssuer ? PublisherType.ISSUER_KEY : PublisherType.KEY;//publisher Type
    
};

exports.PublisherID = PublisherID;

PublisherID.prototype.decode = function(decoder) {
		
		// We have a choice here of one of 4 binary element types.
		var nextTag = decoder.peekStartElementAsLong();
		
		if (null == nextTag) {
			throw new Exception("Cannot parse publisher ID.");
		} 
		
		this.PublisherType = new PublisherType(nextTag); 
		
		if (!this.PublisherType.isTypeTagVal(nextTag)) {
			throw new Exception("Invalid publisher ID, got unexpected type: " + nextTag);
		}
		this.PublisherID = decoder.readBinaryElement(nextTag);
		if (null == _publisherID) {
			throw new ContentDecodingException("Cannot parse publisher ID of type : " + nextTag + ".");
		}
};

PublisherID.prototype.encode = function(encoder) {
	if (!this.validate()) {
		throw new Exception("Cannot encode " + this.getClass().getName() + ": field values missing.");
	}

	encoder.writeElement(this.getElementLabel(), this.PublisherID);
};
	
PublisherID.prototype.getElementLabel = function() { 
	return this.PublisherType.Tag;
};

	
PublisherID.prototype.validate = function(){
	return ((null != id() && (null != type())));
};



