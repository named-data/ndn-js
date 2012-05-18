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
		
		if(LOG>3)console.log('Content Name String '+_Components);
		this.Components = createNameArray(_Components);
	}
	else if(typeof _Components === 'object' && _Components instanceof Array ){
		
		if(LOG>4)console.log('Content Name Array '+_Components);
		this.Components = _Components;

	}
	else if(_Components==null){
		this.Components =[];
	}
	else{

		if(LOG>1)console.log("NO CONTENT NAME GIVEN");

	}
};

function createNameArray(name){

		
	//message = decodeURIComponent(message);
	name = unescape(name);
	
	var array = name.split('/');

	
	if(name[0]=="/")
		array=array.slice(1,array.length);
		
	if(name[name.length-1]=="/")
		array=array.slice(0,array.length-1);
	
	return array;
}


ContentName.prototype.decode = function(/*XMLDecoder*/ decoder)  {
		decoder.readStartElement(this.getElementLabel());

		
		this.Components = new Array(); //new ArrayList<byte []>();

		while (decoder.peekStartElement(CCNProtocolDTags.Component)) {
			this.add(decoder.readBinaryElement(CCNProtocolDTags.Component));
		}
		
		decoder.readEndElement();
};

ContentName.prototype.encode = function(/*XMLEncoder*/ encoder)  {
		
		if( this.Components ==null ) 
			throw new Exception("CANNOT ENCODE EMPTY CONTENT NAME");

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

