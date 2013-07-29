/**
 * @author: Meki Cheraoui
 * See COPYING for copyright and distribution information.
 * This class represents Face Instances
 */

var NetworkProtocol = { TCP:6, UDP:17};

/**
 * @constructor
 */
var FaceInstance  = function FaceInstance(action, publisherPublicKeyDigest, faceID, ipProto, host, port, multicastInterface,
		multicastTTL, freshnessSeconds) {
	this.action = action;
	this.publisherPublicKeyDigest = publisherPublicKeyDigest;
	this.faceID = faceID;
	this.ipProto = ipProto;
	this.host = host;
	this.Port = port;
	this.multicastInterface =multicastInterface;
	this.multicastTTL =multicastTTL;
	this.freshnessSeconds = freshnessSeconds;
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


FaceInstance.prototype.getElementLabel = function() {
  return CCNProtocolDTags.FaceInstance;
};

