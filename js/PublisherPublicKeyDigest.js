/**
 * @author: Meki Cheraoui
 * See COPYING for copyright and distribution information.
 * This class represents PublisherPublicKeyDigest Objects
 */
var PublisherPublicKeyDigest = function PublisherPublicKeyDigest(_pkd){ 
	
 	 //this.PUBLISHER_ID_LEN = 256/8;
	 this.PUBLISHER_ID_LEN = 512/8;
 	 

	 this.publisherPublicKeyDigest = _pkd;
 	 //if( typeof _pkd == "object") this.publisherPublicKeyDigest = _pkd; // Byte Array
 	 //else if( typeof _pkd == "PublicKey") ;//TODO...
    
};

PublisherPublicKeyDigest.prototype.from_ccnb = function( decoder) {		

		this.publisherPublicKeyDigest = decoder.readBinaryElement(this.getElementLabel());
		
		if(LOG>4)console.log('Publisher public key digest is ' + this.publisherPublicKeyDigest);

		if (null == this.publisherPublicKeyDigest) {
			throw new Error("Cannot parse publisher key digest.");
		}
		
		//TODO check if the length of the PublisherPublicKeyDigest is correct ( Security reason)

		if (this.publisherPublicKeyDigest.length != this.PUBLISHER_ID_LEN) {
			if (LOG > 0)
                console.log('LENGTH OF PUBLISHER ID IS WRONG! Expected ' + this.PUBLISHER_ID_LEN + ", got " + this.publisherPublicKeyDigest.length);
			
			//this.publisherPublicKeyDigest = new PublisherPublicKeyDigest(this.PublisherPublicKeyDigest).PublisherKeyDigest;		
		}
	};

PublisherPublicKeyDigest.prototype.to_ccnb= function( encoder) {
		//TODO Check that the ByteArray for the key is present
		if (!this.validate()) {
			throw new Error("Cannot encode : field values missing.");
		}
		if(LOG>3) console.log('PUBLISHER KEY DIGEST IS'+this.publisherPublicKeyDigest);
		encoder.writeElement(this.getElementLabel(), this.publisherPublicKeyDigest);
};
	
PublisherPublicKeyDigest.prototype.getElementLabel = function() { return CCNProtocolDTags.PublisherPublicKeyDigest; };

PublisherPublicKeyDigest.prototype.validate =function() {
		return (null != this.publisherPublicKeyDigest);
};
