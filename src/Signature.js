var CCNProtocolDTags = require('./CCNProtocolDTags').CCNProtocolDTags;


var Signature = function Signature(_Witness,_Signature,_DigestAlgorithm) {
	
    this.Witness = _Witness;//byte [] _witness;
	this.Signature = _Signature;//byte [] _signature;
	this.DigestAlgorithm = _DigestAlgorithm//String _digestAlgorithm;
};

exports.Signature = Signature;


Signature.prototype.decode =function( decoder) {
		decoder.readStartElement(this.getElementLabel());
		if (decoder.peekStartElement(CCNProtocolDTags.DigestAlgorithm)) {
			this.DigestAlgorithm = decoder.readUTF8Element(CCNProtocolDTags.DigestAlgorithm); 
		}
		if (decoder.peekStartElement(CCNProtocolDTags.Witness)) {
			this.Witness = decoder.readBinaryElement(CCNProtocolDTags.Witness); 
		}
		this.Signature = decoder.readBinaryElement(CCNProtocolDTags.SignatureBits);	
		decoder.readEndElement();
	
};


exports.Signature = Signature;

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

