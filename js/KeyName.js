/*
 * @author: ucla-cs
 * This class represents KeyName Objects
 */

var KeyName = function KeyName() {
	

	this.contentName = this.contentName;//contentName
	this.publisherID =this.publisherID;//publisherID

};


KeyName.prototype.from_ccnb=function( decoder){
	

	decoder.readStartElement(this.getElementLabel());

	this.contentName = new ContentName();
	this.contentName.from_ccnb(decoder);
	
	if(LOG>4) console.log('KEY NAME FOUND: ');
	
	if ( PublisherID.peek(decoder) ) {
		this.publisherID = new PublisherID();
		this.publisherID.from_ccnb(decoder);
	}
	
	decoder.readEndElement();
};

KeyName.prototype.to_ccnb = function( encoder) {
	if (!this.validate()) {
		throw new Exception("Cannot encode : field values missing.");
	}
	
	encoder.writeStartElement(this.getElementLabel());
	
	this.contentName.to_ccnb(encoder);
	if (null != this.publisherID)
		this.publisherID.to_ccnb(encoder);

	encoder.writeEndElement();   		
};
	
KeyName.prototype.getElementLabel = function() { return CCNProtocolDTags.KeyName; };

KeyName.prototype.validate = function() {
		// DKS -- do we do recursive validation?
		// null signedInfo ok
		return (null != this.contentName);
};
