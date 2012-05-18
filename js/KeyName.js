/*
 * @author: ucla-cs
 * This class represents KeyName Objects
 */

var KeyName = function KeyName() {
	

	this.ContentName = this.ContentName;//ContentName
	this.PublisherID =this.PublisherID;//PublisherID

};


KeyName.prototype.decode=function( decoder){
	

	decoder.readStartElement(this.getElementLabel());

	this.ContentName = new ContentName();
	this.ContentName.decode(decoder);
	
	if(LOG>4) console.log('KEY NAME FOUND: ');
	
	if ( peek(decoder) ) {
		this.PublisherID = new PublisherID();
		this.PublisherID.decode(decoder);
	}
	
	decoder.readEndElement();
};

KeyName.prototype.encode = function( encoder) {
	if (!this.validate()) {
		throw new Exception("Cannot encode : field values missing.");
	}
	
	encoder.writeStartElement(this.getElementLabel());
	
	this.ContentName.encode(encoder);
	if (null != this.PublisherID)
		this.PublisherID.encode(encoder);

	encoder.writeEndElement();   		
};
	
KeyName.prototype.getElementLabel = function() { return CCNProtocolDTags.KeyName; };

KeyName.prototype.validate = function() {
		// DKS -- do we do recursive validation?
		// null signedInfo ok
		return (null != this.ContentName);
};
