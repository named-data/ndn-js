/*
 * @author: ucla-cs
 * This class represents PublisherPublicKeyDigest Objects
 */
var PublisherPublicKeyDigest = function PublisherPublicKeyDigest(_pkd){ 
	
	
 	 this.PUBLISHER_ID_LEN = 256/8;
 	 
	 this.PublisherPublicKeyDigest = _pkd;
 	 //if( typeof _pkd == "object") this.PublisherPublicKeyDigest = _pkd; // Byte Array
 	 //else if( typeof _pkd == "PublicKey") ;//TODO...
    
 	 

};




PublisherPublicKeyDigest.prototype.decode = function( decoder) {		

		this.PublisherPublicKeyDigest = decoder.readBinaryElement(this.getElementLabel());
		
		if(LOG>4)console.log('Publisher public key digest is ' + this.PublisherPublicKeyDigest);

		if (null == this.PublisherPublicKeyDigest) {
			throw new Exception("Cannot parse publisher key digest.");
		}
		
		//TODO check if the length of the PublisherPublicKeyDigest is correct ( Security reason)

		if (this.PublisherPublicKeyDigest.length != PublisherID.PUBLISHER_ID_LEN) {
			
			console.log('LENGTH OF PUBLISHER ID IS WRONG!');
			
			//this.PublisherPublicKeyDigest = new PublisherPublicKeyDigest(this.PublisherPublicKeyDigest).PublisherKeyDigest;
		
		}
	};

PublisherPublicKeyDigest.prototype.encode= function( encoder) {
		//TODO Check that the ByteArray for the key is present
		/*if (!this.validate()) {
			throw new Exception("Cannot encode : field values missing.");
		}*/
		if(LOG>3) console.log('PUBLISHER KEY DIGEST IS'+this.PublisherPublicKeyDigest);
		encoder.writeElement(this.getElementLabel(), this.PublisherPublicKeyDigest);
};
	
PublisherPublicKeyDigest.prototype.getElementLabel = function() { return CCNProtocolDTags.PublisherPublicKeyDigest; };

PublisherPublicKeyDigest.prototype.validate =function() {
		return (null != this.PublisherKeyDigest);
};
