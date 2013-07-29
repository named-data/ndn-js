/**
 * @author: Meki Cheraoui
 * See COPYING for copyright and distribution information.
 * This class represents Forwarding Entries
 */

/**
 * Create a new ForwardingEntry with the optional arguments.
 * @constructor
 * @param {String} action
 * @param {Name} prefixName
 * @param {PublisherPublicKeyDigest} ccndId
 * @param {number} faceID
 * @param {number} flags
 * @param {number} lifetime in seconds
 */
var ForwardingEntry = function ForwardingEntry(action, prefixName, ccndId, faceID, flags, lifetime) {
	this.action = action;
	this.prefixName = prefixName;
	this.ccndID = ccndId;
	this.faceID = faceID;
	this.flags = flags;
	this.lifetime = lifetime;
};

ForwardingEntry.prototype.from_ccnb =function(
	//XMLDecoder 
	decoder) 
	//throws ContentDecodingException
	{
			decoder.readStartElement(this.getElementLabel());
			if (decoder.peekStartElement(CCNProtocolDTags.Action)) {
				this.action = decoder.readUTF8Element(CCNProtocolDTags.Action); 
			}
			if (decoder.peekStartElement(CCNProtocolDTags.Name)) {
				this.prefixName = new Name();
				this.prefixName.from_ccnb(decoder) ;
			}
			if (decoder.peekStartElement(CCNProtocolDTags.PublisherPublicKeyDigest)) {
				this.CcndId = new PublisherPublicKeyDigest();
				this.CcndId.from_ccnb(decoder);
			}
			if (decoder.peekStartElement(CCNProtocolDTags.FaceID)) {
				this.faceID = decoder.readIntegerElement(CCNProtocolDTags.FaceID); 
			}
			if (decoder.peekStartElement(CCNProtocolDTags.ForwardingFlags)) {
				this.flags = decoder.readIntegerElement(CCNProtocolDTags.ForwardingFlags); 
			}
			if (decoder.peekStartElement(CCNProtocolDTags.FreshnessSeconds)) {
				this.lifetime = decoder.readIntegerElement(CCNProtocolDTags.FreshnessSeconds); 
			}
			decoder.readEndElement();
		};

ForwardingEntry.prototype.to_ccnb =function(
	//XMLEncoder 
encoder) 
{


			//if (!validate()) {
				//throw new ContentEncodingException("Cannot encode " + this.getClass().getName() + ": field values missing.");
			//}
			encoder.writeStartElement(this.getElementLabel());
			if (null != this.action && this.action.length != 0)
				encoder.writeElement(CCNProtocolDTags.Action, this.action);	
			if (null != this.prefixName) {
				this.prefixName.to_ccnb(encoder);
			}
			if (null != this.CcndId) {
				this.CcndId.to_ccnb(encoder);
			}
			if (null != this.faceID) {
				encoder.writeElement(CCNProtocolDTags.FaceID, this.faceID);
			}
			if (null != this.flags) {
				encoder.writeElement(CCNProtocolDTags.ForwardingFlags, this.flags);
			}
			if (null != this.lifetime) {
				encoder.writeElement(CCNProtocolDTags.FreshnessSeconds, this.lifetime);
			}
			encoder.writeEndElement();   			
		};

ForwardingEntry.prototype.getElementLabel = function() { return CCNProtocolDTags.ForwardingEntry; }
