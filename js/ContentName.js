/*
 * @author: ucla-cs
 * This class represents ContentName
 */
 

var ContentName = function ContentName(_Components){


	this.SCHEME = "ccnx:";

	this.ORIGINAL_SCHEME = "ccn:";

	this.SEPARATOR = "/";
	this.ROOT = null;
	
	if( typeof _Components == 'string') {
		this.Components = _Components;
		

	}
	else if(typeof _Components === 'object' && _Components instanceof Array ){
		
		this.Components = _Components;

	}
	else{
		
		console.log("TODO: This should be an array");
		this.Components==_Components;
	}
};




ContentName.prototype.decode = function(/*XMLDecoder*/ decoder)  {
		decoder.readStartElement(this.getElementLabel());

		
		this.Components = new Array(); //new ArrayList<byte []>();

		while (decoder.peekStartElement(CCNProtocolDTags.Component)) {
			this.add(decoder.readBinaryElement(CCNProtocolDTags.Component));
		}
		
		decoder.readEndElement();
};

ContentName.prototype.encode = function(/*XMLEncoder*/ encoder)  {
		
		//TODO Check if parameters are valid

		encoder.writeStartElement(this.getElementLabel());
		var count = this.Components.length;
		for (var i=0; i < count; i++) {
			encoder.writeElement(CCNProtocolDTags.Component, this.Components[i]);
		}
		encoder.writeEndElement();
};

ContentName.prototype.getElementLabel = function(){
	return CCNProtocolDTags.Name;
};

ContentName.prototype.add = function(param){
	return this.Components.push(param);
};

