
var CCNProtocolDTags = require('./CCNProtocolDTags').CCNProtocolDTags;

var ContentName = function ContentName(_Components){


	this.SCHEME = "ccnx:";

	this.ORIGINAL_SCHEME = "ccn:";

	this.SEPARATOR = "/";
	this.ROOT = null;

	this.Components = _Components;
};

exports.ContentName = ContentName;

ContentName.prototype.decode = function(/*XMLDecoder*/ decoder)  {
		decoder.readStartElement(this.getElementLabel());

		this.Components = new Array(); //new ArrayList<byte []>();

		while (decoder.peekStartElement(CCNProtocolDTags.Component)) {
			this.Components.add(decoder.readBinaryElement(CCNProtocolDTags.Component));
		}

		decoder.readEndElement();
};

ContentName.prototype.encode = function(/*XMLEncoder*/ encoder)  {
		//if (!validate()) {
			//throw new ContentEncodingException("Cannot encode " + this.getClass().getName() + ": field values missing.");
		//}

		encoder.writeStartElement(this.getElementLabel());
		var count = this.Components.length;
		for (var i=0; i < count; ++i) {
			encoder.writeElement(CCNProtocolDTags.Component, this.Components.get(i));
		}
		encoder.writeEndElement();
};

ContentName.prototype.getElementLabel = function(){
	return CCNProtocolDTags.Name;
};
