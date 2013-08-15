/**
 * @author: Meki Cheraoui
 * See COPYING for copyright and distribution information.
 * This class represents Publisher and PublisherType Objects
 */

/**
 * @constructor
 */
var PublisherType = function PublisherType(tag){
    	this.KEY =(NDNProtocolDTags.PublisherPublicKeyDigest);
    	this.CERTIFICATE= (NDNProtocolDTags.PublisherCertificateDigest);
    	this.ISSUER_KEY=	(NDNProtocolDTags.PublisherIssuerKeyDigest);
    	this.ISSUER_CERTIFICATE	=(NDNProtocolDTags.PublisherIssuerCertificateDigest);

    	this.Tag = tag;
}; 

var isTypeTagVal = function(tagVal) {
		if ((tagVal == NDNProtocolDTags.PublisherPublicKeyDigest) ||
			(tagVal == NDNProtocolDTags.PublisherCertificateDigest) ||
			(tagVal == NDNProtocolDTags.PublisherIssuerKeyDigest) ||
			(tagVal == NDNProtocolDTags.PublisherIssuerCertificateDigest)) {
			return true;
		}
		return false;
};

/**
 * @constructor
 */
var PublisherID = function PublisherID() {

	this.PUBLISHER_ID_DIGEST_ALGORITHM = "SHA-256";
	this.PUBLISHER_ID_LEN = 256/8;
    
	//TODO, implement publisherID creation and key creation

    //TODO implement generatePublicKeyDigest
    this.publisherID =null;//= generatePublicKeyDigest(key);//ByteArray
    
    //TODO implement generate key
    //CryptoUtil.generateKeyID(PUBLISHER_ID_DIGEST_ALGORITHM, key);
    this.publisherType = null;//isIssuer ? PublisherType.ISSUER_KEY : PublisherType.KEY;//publisher Type
    
};


PublisherID.prototype.from_ndnb = function(decoder) {
		
		// We have a choice here of one of 4 binary element types.
		var nextTag = decoder.peekStartElementAsLong();
		
		if (null == nextTag) {
			throw new Error("Cannot parse publisher ID.");
		} 
		
		this.publisherType = new PublisherType(nextTag); 
		
		if (!isTypeTagVal(nextTag)) {
			throw new Error("Invalid publisher ID, got unexpected type: " + nextTag);
		}
		this.publisherID = decoder.readBinaryElement(nextTag);
		if (null == this.publisherID) {
			throw new ContentDecodingException(new Error("Cannot parse publisher ID of type : " + nextTag + "."));
		}
};

PublisherID.prototype.to_ndnb = function(encoder) {
	if (!this.validate()) {
		throw new Error("Cannot encode " + this.getClass().getName() + ": field values missing.");
	}

	encoder.writeElement(this.getElementLabel(), this.publisherID);
};
	
PublisherID.peek = function(/* XMLDecoder */ decoder) {

		//Long
		var nextTag = decoder.peekStartElementAsLong();
		
		if (null == nextTag) {
			// on end element
			return false;
		}
		return (isTypeTagVal(nextTag));
	};

PublisherID.prototype.getElementLabel = function() { 
	return this.publisherType.Tag;
};

PublisherID.prototype.validate = function(){
	return ((null != id() && (null != type())));
};



