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
 * @param {PublisherPublicKeyDigest} ndndId
 * @param {number} faceID
 * @param {number} flags
 * @param {number} lifetime in seconds
 */
var ForwardingEntry = function ForwardingEntry(action, prefixName, ndndId, faceID, flags, lifetime) {
	this.action = action;
	this.prefixName = prefixName;
	this.ndndID = ndndId;
	this.faceID = faceID;
	this.flags = flags;
	this.lifetime = lifetime;
};

ForwardingEntry.prototype.from_ndnb =function(
	//XMLDecoder 
	decoder) 
	//throws ContentDecodingException
	{
			decoder.readStartElement(this.getElementLabel());
			if (decoder.peekStartElement(NDNProtocolDTags.Action)) {
				this.action = decoder.readUTF8Element(NDNProtocolDTags.Action); 
			}
			if (decoder.peekStartElement(NDNProtocolDTags.Name)) {
				this.prefixName = new Name();
				this.prefixName.from_ndnb(decoder) ;
			}
			if (decoder.peekStartElement(NDNProtocolDTags.PublisherPublicKeyDigest)) {
				this.NdndId = new PublisherPublicKeyDigest();
				this.NdndId.from_ndnb(decoder);
			}
			if (decoder.peekStartElement(NDNProtocolDTags.FaceID)) {
				this.faceID = decoder.readIntegerElement(NDNProtocolDTags.FaceID); 
			}
			if (decoder.peekStartElement(NDNProtocolDTags.ForwardingFlags)) {
				this.flags = decoder.readIntegerElement(NDNProtocolDTags.ForwardingFlags); 
			}
			if (decoder.peekStartElement(NDNProtocolDTags.FreshnessSeconds)) {
				this.lifetime = decoder.readIntegerElement(NDNProtocolDTags.FreshnessSeconds); 
			}
			decoder.readEndElement();
		};

ForwardingEntry.prototype.to_ndnb =function(
	//XMLEncoder 
encoder) 
{


			//if (!validate()) {
				//throw new ContentEncodingException("Cannot encode " + this.getClass().getName() + ": field values missing.");
			//}
			encoder.writeStartElement(this.getElementLabel());
			if (null != this.action && this.action.length != 0)
				encoder.writeElement(NDNProtocolDTags.Action, this.action);	
			if (null != this.prefixName) {
				this.prefixName.to_ndnb(encoder);
			}
			if (null != this.NdndId) {
				this.NdndId.to_ndnb(encoder);
			}
			if (null != this.faceID) {
				encoder.writeElement(NDNProtocolDTags.FaceID, this.faceID);
			}
			if (null != this.flags) {
				encoder.writeElement(NDNProtocolDTags.ForwardingFlags, this.flags);
			}
			if (null != this.lifetime) {
				encoder.writeElement(NDNProtocolDTags.FreshnessSeconds, this.lifetime);
			}
			encoder.writeEndElement();   			
		};

ForwardingEntry.prototype.getElementLabel = function() { return NDNProtocolDTags.ForwardingEntry; }
