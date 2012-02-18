
var PublisherID = require('./PublisherID').PublisherID;
var CCNProtocolDTags = require('./CCNProtocolDTags').CCNProtocolDTags;

var PublisherPublicKeyDigest = function PublisherPublicKeyDigest(_pkd){ 
	
 	 if( typeof _pkd == "ByteArray") this.PublisherPublicKeyDigest = _pkd; // Byte Array
 	 else if( typeof _pkd == "PublicKey") ;//TODO...
    
};

exports.PublisherPublicKeyDigest = PublisherPublicKeyDigest;


PublisherPublicKeyDigest.prototype.decode = function( decoder) {		

		this.PublisherPublicKeyDigest = decoder.readBinaryElement(this.getElementLabel());
		if (null == this.PublisherPublicKeyDigest) {
			throw new Exception("Cannot parse publisher key digest.");
		}
		if (this.PublisherPublicKeyDigest.length != PublisherID.PUBLISHER_ID_LEN) {
			
			this.PublisherPublicKeyDigest = new PublisherPublicKeyDigest(this.PublisherPublicKeyDigest).PublisherKeyDigest;
		}
	};

PublisherPublicKeyDigest.prototype.encode= function( encoder) {
		if (!this.validate()) {
			throw new Exception("Cannot encode : field values missing.");
		}
		this.encoder.writeElement(this.getElementLabel(), this.PublisherKeyDigest);
};
	
PublisherPublicKeyDigest.prototype.getElementLabel = function() { return CCNProtocolDTags.PublisherPublicKeyDigest; };

PublisherPublicKeyDigest.prototype.validate =function() {
		return (null != this.PublisherKeyDigest);
};
