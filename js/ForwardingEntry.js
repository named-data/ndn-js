/*
 * @author: ucla-cs
 * This class represents Forwarding Entries
 */

var ForwardingEntry = function ForwardingEntry(
                                               //ActionType 
		_action, 
		//ContentName 
		_prefixName, 
		//PublisherPublicKeyDigest
		_ccndId, 
		//Integer 
		_faceID, 
		//Integer 
		_flags, 
		//Integer 
		_lifetime){
		
		
	
		//String
	this.Action = _action;
		//ContentName\
	this.PrefixName = _prefixName;
		//PublisherPublicKeyDigest 
	this.CCNID = _ccndId;
		//Integer		
	this.FaceID = _faceID;
		//Integer		
	this.Flags = _flags;
		//Integer 		
	this.Lifetime = _lifetime;  // in seconds

};

ForwardingEntry.prototype.decode =function(
	//XMLDecoder 
	decoder) 
	//throws ContentDecodingException
	{
			decoder.readStartElement(this.getElementLabel());
			if (decoder.peekStartElement(CCNProtocolDTags.Action)) {
				this.Action = decoder.readUTF8Element(CCNProtocolDTags.Action); 
			}
			if (decoder.peekStartElement(CCNProtocolDTags.Name)) {
				this.PrefixName = new ContentName();
				this.PrefixName.decode(decoder) ;
			}
			if (decoder.peekStartElement(CCNProtocolDTags.PublisherPublicKeyDigest)) {
				this.CcndId = new PublisherPublicKeyDigest();
				this.CcndId.decode(decoder);
			}
			if (decoder.peekStartElement(CCNProtocolDTags.FaceID)) {
				this.FaceID = decoder.readIntegerElement(CCNProtocolDTags.FaceID); 
			}
			if (decoder.peekStartElement(CCNProtocolDTags.ForwardingFlags)) {
				this.Flags = decoder.readIntegerElement(CCNProtocolDTags.ForwardingFlags); 
			}
			if (decoder.peekStartElement(CCNProtocolDTags.FreshnessSeconds)) {
				this.Lifetime = decoder.readIntegerElement(CCNProtocolDTags.FreshnessSeconds); 
			}
			decoder.readEndElement();
		};

		/**
		 * Used by NetworkObject to encode the object to a network stream.
		 * @see org.ccnx.ccn.impl.encoding.XMLEncodable
		 */
ForwardingEntry.prototype.encode =function(
	//XMLEncoder 
encoder) 
{


			//if (!validate()) {
				//throw new ContentEncodingException("Cannot encode " + this.getClass().getName() + ": field values missing.");
			//}
			encoder.writeStartElement(this.getElementLabel());
			if (null != this.Action && this.Action.length != 0)
				encoder.writeElement(CCNProtocolDTags.Action, this.Action);	
			if (null != this.PrefixName) {
				this.PrefixName.encode(encoder);
			}
			if (null != this.CcndId) {
				this.CcndId.encode(encoder);
			}
			if (null != this.FaceID) {
				encoder.writeElement(CCNProtocolDTags.FaceID, this.FaceID);
			}
			if (null != this.Flags) {
				encoder.writeElement(CCNProtocolDTags.ForwardingFlags, this.Flags);
			}
			if (null != this.Lifetime) {
				encoder.writeElement(CCNProtocolDTags.FreshnessSeconds, this.Lifetime);
			}
			encoder.writeEndElement();   			
		};

ForwardingEntry.prototype.getElementLabel = function() { return CCNProtocolDTags.ForwardingEntry; }
