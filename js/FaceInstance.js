


var FaceInstance  = function FaceInstance(
	    _Action,
		_PublisherPublicKeyDigest,
		_FaceID,
		_IPProto,
		_Host,
		_Port,
		_MulticastInterface,
		_MulticastTTL,
		_FreshnessSeconds,){
		
	
	this.Action = _Action,
	this.PublisherPublicKeyDigest = _PublisherPublicKeyDigest,
	this.FaceID = _FaceID,
	this.IPProto = _IPProto,
	this.Host = _Host,
	this.Port = _Port,
	this.MulticastInterface =_MulticastInterface,
	this.MulticastTTL =_MulticastTTL,
	this.FreshnessSeconds = _FreshnessSeconds,
	
	
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
FaceInstance.prototype.decode(//XMLDecoder 
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
public void encode(XMLEncoder encoder) throws ContentEncodingException {
	if (!validate()) {
		throw new ContentEncodingException("Cannot encode " + this.getClass().getName() + ": field values missing.");
	}
	encoder.writeStartElement(getElementLabel());
	if (null != _action && _action.length() != 0)
		encoder.writeElement(CCNProtocolDTags.Action, _action);	
	if (null != _ccndID) {
		_ccndID.encode(encoder);
	}
	if (null != _faceID) {
		encoder.writeElement(CCNProtocolDTags.FaceID, _faceID);
	}
	if (null != _ipProto) {
		encoder.writeElement(CCNProtocolDTags.IPProto, _ipProto.value());
	}
	if (null != _host && _host.length() != 0) {
		encoder.writeElement(CCNProtocolDTags.Host, _host);	
	}
	if (null != _port) {
		encoder.writeElement(CCNProtocolDTags.Port, _port);
	}
	if (null != _multicastInterface && _multicastInterface.length() != 0) {
		encoder.writeElement(CCNProtocolDTags.MulticastInterface, _multicastInterface);
	}
	if (null != _multicastTTL) {
		encoder.writeElement(CCNProtocolDTags.MulticastTTL, _multicastTTL);
	}
	if (null != _lifetime) {
		encoder.writeElement(CCNProtocolDTags.FreshnessSeconds, _lifetime);
	}
	encoder.writeEndElement();   			
}


FaceInstance.prototype.getElementLabel= function(){return CCNProtocolDTags.FaceInstance;};

