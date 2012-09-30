/*
 * @author: ucla-cs
 * This class represents Signature Objects
 */


var Signature = function Signature(_Witness,_Signature,_DigestAlgorithm) {
	
    this.Witness = _Witness;//byte [] _witness;
	this.Signature = _Signature;//byte [] _signature;
	this.DigestAlgorithm = _DigestAlgorithm//String _digestAlgorithm;
};

var generateSignature = function(contentName,content,signedinfo){
	
	var enc = new BinaryXMLEncoder();
	contentName.encode(enc);
	var hex1 = toHex(enc.getReducedOstream());

	var enc = new BinaryXMLEncoder();
	content.to_ccnb(enc);
	var hex2 = toHex(enc.getReducedOstream());

	var enc = new BinaryXMLEncoder();
	signedinfo.encode(enc);
	var hex3 = toHex(enc.getReducedOstream());

	var hex = hex1+hex2+hex3;

	//globalKeyManager.sig

};

Signature.prototype.decode =function( decoder) {
		decoder.readStartElement(this.getElementLabel());
		
		if(LOG>4)console.log('STARTED DECODING SIGNATURE ');
		
		if (decoder.peekStartElement(CCNProtocolDTags.DigestAlgorithm)) {
			
			if(LOG>4)console.log('DIGIEST ALGORITHM FOUND');
			this.DigestAlgorithm = decoder.readUTF8Element(CCNProtocolDTags.DigestAlgorithm); 
		}
		if (decoder.peekStartElement(CCNProtocolDTags.Witness)) {
			if(LOG>4)console.log('WITNESS FOUND FOUND');
			this.Witness = decoder.readBinaryElement(CCNProtocolDTags.Witness); 
		}
		
		//FORCE TO READ A SIGNATURE

			//if(LOG>4)console.log('SIGNATURE FOUND ');
			this.Signature = decoder.readBinaryElement(CCNProtocolDTags.SignatureBits);	
			if(LOG>4)console.log('READ SIGNATURE ');

		decoder.readEndElement();
	
};


Signature.prototype.encode= function( encoder){
    	
	if (!this.validate()) {
		throw new Exception("Cannot encode: field values missing.");
	}
	
	encoder.writeStartElement(this.getElementLabel());
	
	if ((null != this.DigestAlgorithm) && (!this.DigestAlgorithm.equals(CCNDigestHelper.DEFAULT_DIGEST_ALGORITHM))) {
		encoder.writeElement(CCNProtocolDTags.DigestAlgorithm, OIDLookup.getDigestOID(this.DigestAlgorithm));
	}
	
	if (null != this.Witness) {
		// needs to handle null witness
		encoder.writeElement(CCNProtocolDTags.Witness, this.Witness);
	}

	encoder.writeElement(CCNProtocolDTags.SignatureBits, this.Signature);

	encoder.writeEndElement();   		
};

Signature.prototype.getElementLabel = function() { return CCNProtocolDTags.Signature; };


Signature.prototype.validate = function() {
		return null != this.Signature;
};

