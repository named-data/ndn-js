/*
 * @author: ucla-cs
 * This class represents PublisherPublicKeyDigest Objects
 */
var PublisherPublicKeyDigest = function PublisherPublicKeyDigest(_pkd){ 
	
 	 if( typeof _pkd == "ByteArray") this.PublisherPublicKeyDigest = _pkd; // Byte Array
 	 else if( typeof _pkd == "PublicKey") ;//TODO...
    
};

PublisherPublicKeyDigest.prototype.decode = function( decoder) {		

		this.PublisherPublicKeyDigest = decoder.readBinaryElement(this.getElementLabel());
		if (null == this.PublisherPublicKeyDigest) {
			throw new Exception("Cannot parse publisher key digest.");
		}
		
		//TODO check if the length of the PublisherPublicKeyDigest is correct ( Security reason)

		/*if (this.PublisherPublicKeyDigest.length != PublisherID.PUBLISHER_ID_LEN) {
			console.log('SHOULD NOT GO HERE !!!!!!!!!!!!!!!!!!');
			this.PublisherPublicKeyDigest = new PublisherPublicKeyDigest(this.PublisherPublicKeyDigest).PublisherKeyDigest;
		}*/
	};

PublisherPublicKeyDigest.prototype.encode= function( encoder) {
		//TODO Check that the ByteArray for the key is present
		/*if (!this.validate()) {
			throw new Exception("Cannot encode : field values missing.");
		}*/
	
		if (this.PublisherKeyDigest!=null)this.encoder.writeElement(this.getElementLabel(), this.PublisherKeyDigest);
};
	
PublisherPublicKeyDigest.prototype.getElementLabel = function() { return CCNProtocolDTags.PublisherPublicKeyDigest; };

PublisherPublicKeyDigest.prototype.validate =function() {
		return (null != this.PublisherKeyDigest);
};
