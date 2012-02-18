
var CCNProtocolDTags = require('./CCNProtocolDTags').CCNProtocolDTags;

var ContentObject = function ContentObject(_Name,_SignedInfo,_Content,_Signature){
	
	
	this.Name = _Name;
	this.SignedInfo = _SignedInfo;
	this.Content=_Content;
	this.Signature = _Signature;

};

exports.ContentObject = ContentObject;


ContentObject.prototype.decode = function(/*XMLDecoder*/ decoder) {
	
		decoder.readStartElement(this.getElementLabel());

		this.Signature = new Signature();
		this.Signature.decode(decoder);

		this.Name = new ContentName();
		this.Name.decode(decoder);

		this.SignedInfo = new SignedInfo();
		this.SignedInfo.decode(decoder);

		this.Content = decoder.readBinaryElement(CCNProtocolDTags.Content);

		decoder.readEndElement();

};


ContentObject.prototype.encode = function(/*XMLEncoder*/ encoder)  {
	
	if((null == this.Name) && (null==this.SignedInfo) && (null ==this.Signature)){
		
		throw "Illegal input inside encode of Content Object";
	}
	/* 
	 * if (!validate()) {
			throw new ContentEncodingException("Cannot encode " + this.getClass().getName() + ": field values missing.");
		}*/
		
	encoder.writeStartElement(this.getElementLabel());

	this.Signature.encode(encoder);
	this.Name.encode(encoder);
	this.SignedInfo.encode(encoder);

	encoder.writeElement(CCNProtocolDTags.Content, this.Content);

	encoder.writeEndElement();

};


ContentObject.prototype.getElementLabel= function(){returnCCNProtocolDTags.ContentObject;};