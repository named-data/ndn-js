/**
 * @author: Meki Cheraoui
 * See COPYING for copyright and distribution information.
 * This class represents Face Instances
 */

var NetworkProtocol = { TCP:6, UDP:17};

var FaceInstance  = function FaceInstance(
	    _action,
		_publisherPublicKeyDigest,
		_faceID,
		_ipProto,
		_host,
		_port,
		_multicastInterface,
		_multicastTTL,
		_freshnessSeconds){
	

	this.action = _action;
	this.publisherPublicKeyDigest = _publisherPublicKeyDigest;
	this.faceID = _faceID;
	this.ipProto = _ipProto;
	this.host = _host;
	this.Port = _port;
	this.multicastInterface =_multicastInterface;
	this.multicastTTL =_multicastTTL;
	this.freshnessSeconds = _freshnessSeconds;
	
	//action           ::= ("newface" | "destroyface" | "queryface")
	//publisherPublicKeyDigest ::= SHA-256 digest
	//faceID           ::= nonNegativeInteger
	//ipProto          ::= nonNegativeInteger [IANA protocol number, 6=TCP, 17=UDP]
	//Host             ::= textual representation of numeric IPv4 or IPv6 address
	//Port             ::= nonNegativeInteger [1..65535]
	//MulticastInterface ::= textual representation of numeric IPv4 or IPv6 address
	//MulticastTTL     ::= nonNegativeInteger [1..255]
	//freshnessSeconds ::= nonNegativeInteger

};

/**
 * Used by NetworkObject to decode the object from a network stream.
 */
FaceInstance.prototype.from_ccnb = function(//XMLDecoder 
	decoder) {

	decoder.readStartElement(this.getElementLabel());
	
	if (decoder.peekStartElement(CCNProtocolDTags.Action)) {
		
		this.action = decoder.readUTF8Element(CCNProtocolDTags.Action);
		
	}
	if (decoder.peekStartElement(CCNProtocolDTags.PublisherPublicKeyDigest)) {
		
		this.publisherPublicKeyDigest = new PublisherPublicKeyDigest();
		this.publisherPublicKeyDigest.from_ccnb(decoder);
		
	}
	if (decoder.peekStartElement(CCNProtocolDTags.FaceID)) {
		
		this.faceID = decoder.readIntegerElement(CCNProtocolDTags.FaceID);
		
	}
	if (decoder.peekStartElement(CCNProtocolDTags.IPProto)) {
		
		//int
		var pI = decoder.readIntegerElement(CCNProtocolDTags.IPProto);
		
		this.ipProto = null;
		
		if (NetworkProtocol.TCP == pI) {
			
			this.ipProto = NetworkProtocol.TCP;
			
		} else if (NetworkProtocol.UDP == pI) {
			
			this.ipProto = NetworkProtocol.UDP;
			
		} else {
			
			throw new Error("FaceInstance.decoder.  Invalid " + 
					CCNProtocolDTags.tagToString(CCNProtocolDTags.IPProto) + " field: " + pI);
			
		}
	}
	
	if (decoder.peekStartElement(CCNProtocolDTags.Host)) {
		
		this.host = decoder.readUTF8Element(CCNProtocolDTags.Host);
		
	}
	
	if (decoder.peekStartElement(CCNProtocolDTags.Port)) {
		this.Port = decoder.readIntegerElement(CCNProtocolDTags.Port); 
	}
	
	if (decoder.peekStartElement(CCNProtocolDTags.MulticastInterface)) {
		this.multicastInterface = decoder.readUTF8Element(CCNProtocolDTags.MulticastInterface); 
	}
	
	if (decoder.peekStartElement(CCNProtocolDTags.MulticastTTL)) {
		this.multicastTTL = decoder.readIntegerElement(CCNProtocolDTags.MulticastTTL); 
	}
	
	if (decoder.peekStartElement(CCNProtocolDTags.FreshnessSeconds)) {
		this.freshnessSeconds = decoder.readIntegerElement(CCNProtocolDTags.FreshnessSeconds); 
	}
	decoder.readEndElement();
}

/**
 * Used by NetworkObject to encode the object to a network stream.
 */
FaceInstance.prototype.to_ccnb = function(//XMLEncoder
	encoder){

	//if (!this.validate()) {
		//throw new Error("Cannot encode : field values missing.");
		//throw new Error("")
	//}
	encoder.writeStartElement(this.getElementLabel());
	
	if (null != this.action && this.action.length != 0)
		encoder.writeElement(CCNProtocolDTags.Action, this.action);	
	
	if (null != this.publisherPublicKeyDigest) {
		this.publisherPublicKeyDigest.to_ccnb(encoder);
	}
	if (null != this.faceID) {
		encoder.writeElement(CCNProtocolDTags.FaceID, this.faceID);
	}
	if (null != this.ipProto) {
		//encoder.writeElement(CCNProtocolDTags.IPProto, this.IpProto.value());
		encoder.writeElement(CCNProtocolDTags.IPProto, this.ipProto);
	}
	if (null != this.host && this.host.length != 0) {
		encoder.writeElement(CCNProtocolDTags.Host, this.host);	
	}
	if (null != this.Port) {
		encoder.writeElement(CCNProtocolDTags.Port, this.Port);
	}
	if (null != this.multicastInterface && this.multicastInterface.length != 0) {
		encoder.writeElement(CCNProtocolDTags.MulticastInterface, this.multicastInterface);
	}
	if (null !=  this.multicastTTL) {
		encoder.writeElement(CCNProtocolDTags.MulticastTTL, this.multicastTTL);
	}
	if (null != this.freshnessSeconds) {
		encoder.writeElement(CCNProtocolDTags.FreshnessSeconds, this.freshnessSeconds);
	}
	encoder.writeEndElement();   			
}


FaceInstance.prototype.getElementLabel= function(){return CCNProtocolDTags.FaceInstance;};

