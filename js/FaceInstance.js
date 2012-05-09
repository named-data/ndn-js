


var FaceInstance  = function FaceInstance(
	    _Action,
		_PublisherPublicKeyDigest,
		_FaceID,
		_IPProto,
		_Host,
		_Port,
		_MulticastInterface,
		_MulticastTTL,
		_FreshnessSeconds){
	

	this.Action = _Action;
	this.PublisherPublicKeyDigest = _PublisherPublicKeyDigest;
	this.FaceID = _FaceID;
	this.IPProto = _IPProto;
	this.Host = _Host;
	this.Port = _Port;
	this.MulticastInterface =_MulticastInterface;
	this.MulticastTTL =_MulticastTTL;
	this.FreshnessSeconds = _FreshnessSeconds;
	
	//Action           ::= ("newface" | "destroyface" | "queryface")
	//PublisherPublicKeyDigest ::= SHA-256 digest
	//FaceID           ::= nonNegativeInteger
	//IPProto          ::= nonNegativeInteger [IANA protocol number, 6=TCP, 17=UDP]
	//Host             ::= textual representation of numeric IPv4 or IPv6 address
	//Port             ::= nonNegativeInteger [1..65535]
	//MulticastInterface ::= textual representation of numeric IPv4 or IPv6 address
	//MulticastTTL     ::= nonNegativeInteger [1..255]
	//FreshnessSeconds ::= nonNegativeInteger

};

/**
 * Used by NetworkObject to decode the object from a network stream.
 * @see org.ccnx.ccn.impl.encoding.XMLEncodable
 */
FaceInstance.prototype.decode = function(//XMLDecoder 
	decoder) {

	decoder.readStartElement(this.getElementLabel());
	
	if (decoder.peekStartElement(CCNProtocolDTags.Action)) {
		
		this.Action = decoder.readUTF8Element(CCNProtocolDTags.Action);
		
	}
	if (decoder.peekStartElement(CCNProtocolDTags.PublisherPublicKeyDigest)) {
		
		this.PublisherPublicKeyDigest = new PublisherPublicKeyDigest();
		this.PublisherPublicKeyDigest.decode(decoder);
		
	}
	if (decoder.peekStartElement(CCNProtocolDTags.FaceID)) {
		
		this.FaceID = decoder.readIntegerElement(CCNProtocolDTags.FaceID);
		
	}
	if (decoder.peekStartElement(CCNProtocolDTags.IPProto)) {
		
		//int
		var pI = decoder.readIntegerElement(CCNProtocolDTags.IPProto);
		
		this.IPProto = null;
		
		if (NetworkProtocol.TCP.value().intValue() == pI) {
			
			this.IPProto = NetworkProtocol.TCP;
			
		} else if (NetworkProtocol.UDP.value().intValue() == pI) {
			
			this.IPProto = NetworkProtocol.UDP;
			
		} else {
			
			throw new Exception("FaceInstance.decoder.  Invalid " + 
					CCNProtocolDTags.tagToString(CCNProtocolDTags.IPProto) + " field: " + pI);
			
		}
	}
	
	if (decoder.peekStartElement(CCNProtocolDTags.Host)) {
		
		this.Host = decoder.readUTF8Element(CCNProtocolDTags.Host);
		
	}
	
	if (decoder.peekStartElement(CCNProtocolDTags.Port)) {
		this.Port = decoder.readIntegerElement(CCNProtocolDTags.Port); 
	}
	
	if (decoder.peekStartElement(CCNProtocolDTags.MulticastInterface)) {
		this.MulticastInterface = decoder.readUTF8Element(CCNProtocolDTags.MulticastInterface); 
	}
	
	if (decoder.peekStartElement(CCNProtocolDTags.MulticastTTL)) {
		this.MulticastTTL = decoder.readIntegerElement(CCNProtocolDTags.MulticastTTL); 
	}
	
	if (decoder.peekStartElement(CCNProtocolDTags.FreshnessSeconds)) {
		this.FreshnessSeconds = decoder.readIntegerElement(CCNProtocolDTags.FreshnessSeconds); 
	}
	
	decoder.readEndElement();
}

/**
 * Used by NetworkObject to encode the object to a network stream.
 * @see org.ccnx.ccn.impl.encoding.XMLEncodable
 */
FaceInstance.prototype.encode = function(//XMLEncoder
	encoder){

	//if (!this.validate()) {
		//throw new Exception("Cannot encode : field values missing.");
		//throw new Exception("")
	//}
	encoder.writeStartElement(this.getElementLabel());
	if (null != this.Action && this.Action.length != 0)
		encoder.writeElement(CCNProtocolDTags.Action, this.Action);	
	if (null != this.PublisherPublicKeyDigest) {
		this.PublisherPublicKeyDigest.encode(encoder);
	}
	if (null != this.FaceID) {
		encoder.writeElement(CCNProtocolDTags.FaceID, this.FaceID);
	}
	if (null != this.IPProto) {
		//encoder.writeElement(CCNProtocolDTags.IPProto, this.IpProto.value());
		encoder.writeElement(CCNProtocolDTags.IPProto, this.IPProto);
	}
	if (null != this.Host && this.Host.length != 0) {
		encoder.writeElement(CCNProtocolDTags.Host, this.Host);	
	}
	if (null != this.Port) {
		encoder.writeElement(CCNProtocolDTags.Port, this.Port);
	}
	if (null != this.MulticastInterface && this.MulticastInterface.length != 0) {
		encoder.writeElement(CCNProtocolDTags.MulticastInterface, this.MulticastInterface);
	}
	if (null !=  this.MulticastTTL) {
		encoder.writeElement(CCNProtocolDTags.MulticastTTL, this.MulticastTTL);
	}
	if (null != this.FreshnessSeconds) {
		encoder.writeElement(CCNProtocolDTags.FreshnessSeconds, this.FreshnessSeconds);
	}
	encoder.writeEndElement();   			
}




FaceInstance.prototype.getElementLabel= function(){return CCNProtocolDTags.FaceInstance;};

