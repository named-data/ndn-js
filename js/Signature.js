/*
 * @author: ucla-cs
 * This class represents Signature Objects
 */


var Signature = function Signature(_witness,_signature,_digestAlgorithm) {
	
    this.Witness = _witness;//byte [] _witness;
	this.signature = _signature;//byte [] _signature;
	this.digestAlgorithm = _digestAlgorithm//String _digestAlgorithm;
};

var generateSignature = function(contentName,content,signedinfo){
	
	var enc = new BinaryXMLEncoder();
	contentName.to_ccnb(enc);
	var hex1 = toHex(enc.getReducedOstream());

	var enc = new BinaryXMLEncoder();
	content.to_ccnb(enc);
	var hex2 = toHex(enc.getReducedOstream());

	var enc = new BinaryXMLEncoder();
	signedinfo.to_ccnb(enc);
	var hex3 = toHex(enc.getReducedOstream());

	var hex = hex1+hex2+hex3;

	//globalKeyManager.sig

};

Signature.prototype.from_ccnb =function( decoder) {
		decoder.readStartElement(this.getElementLabel());
		
		if(LOG>4)console.log('STARTED DECODING SIGNATURE ');
		
		if (decoder.peekStartElement(CCNProtocolDTags.DigestAlgorithm)) {
			
			if(LOG>4)console.log('DIGIEST ALGORITHM FOUND');
			this.digestAlgorithm = decoder.readUTF8Element(CCNProtocolDTags.DigestAlgorithm); 
		}
		if (decoder.peekStartElement(CCNProtocolDTags.Witness)) {
			if(LOG>4)console.log('WITNESS FOUND FOUND');
			this.Witness = decoder.readBinaryElement(CCNProtocolDTags.Witness); 
		}
		
		//FORCE TO READ A SIGNATURE

			//if(LOG>4)console.log('SIGNATURE FOUND ');
			this.signature = decoder.readBinaryElement(CCNProtocolDTags.SignatureBits);	
			if(LOG>4)console.log('READ SIGNATURE ');

		decoder.readEndElement();
	
};


Signature.prototype.to_ccnb= function( encoder){
    	
	if (!this.validate()) {
		throw new Exception("Cannot encode: field values missing.");
	}
	
	encoder.writeStartElement(this.getElementLabel());
	
	if ((null != this.digestAlgorithm) && (!this.digestAlgorithm.equals(CCNDigestHelper.DEFAULT_DIGEST_ALGORITHM))) {
		encoder.writeElement(CCNProtocolDTags.DigestAlgorithm, OIDLookup.getDigestOID(this.DigestAlgorithm));
	}
	
	if (null != this.Witness) {
		// needs to handle null witness
		encoder.writeElement(CCNProtocolDTags.Witness, this.Witness);
	}

	encoder.writeElement(CCNProtocolDTags.SignatureBits, this.signature);

	encoder.writeEndElement();   		
};

Signature.prototype.getElementLabel = function() { return CCNProtocolDTags.Signature; };


Signature.prototype.validate = function() {
		return null != this.signature;
};

