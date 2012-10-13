/*
 * @author: ucla-cs
 * See COPYING for copyright and distribution information.
 * This class represents a Name
 */
 

var Name = function Name(_components){

	if( typeof _components == 'string') {
		
		if(LOG>3)console.log('Content Name String '+_components);
		this.components = Name.makeBlob(Name.createNameArray(_components));
	}
	else if(typeof _components === 'object' && _components instanceof Array ){
		
		if(LOG>4)console.log('Content Name Array '+_components);
		this.components = Name.makeBlob(_components);

	}
	else if(_components==null){
		this.components =[];
	}
	else{

		if(LOG>1)console.log("NO CONTENT NAME GIVEN");

	}
};

Name.prototype.getName=function(){
	
	var output = "";
	
	for(var i=0;i<this.components.length;i++){
		output+= "/"+ DataUtils.toString(this.components[i]);
	}
	
	return output;
	
};

Name.makeBlob=function(name){
	
	var blobArrays = new Array(name.length);

	for(var i=0;i<name.length;i++){
		if(typeof name[i] == 'string')
			blobArrays[i]= DataUtils.toNumbersFromString( name[i] );
		else if(typeof name[i] == 'object')
			blobArrays[i]= name[i] ;
		else 
			if(LOG>4)console.log('NAME COMPONENT INVALID');
	}
	
	return blobArrays;
};

Name.createNameArray=function(name){


	name = unescape(name);
	
	var array = name.split('/');

	
	if(name[0]=="/")
		array=array.slice(1,array.length);
		
	if(name[name.length-1]=="/")
		array=array.slice(0,array.length-1);
	
	return array;
}


Name.prototype.from_ccnb = function(/*XMLDecoder*/ decoder)  {
		decoder.readStartElement(this.getElementLabel());

		
		this.components = new Array(); //new ArrayList<byte []>();

		while (decoder.peekStartElement(CCNProtocolDTags.Component)) {
			this.add(decoder.readBinaryElement(CCNProtocolDTags.Component));
		}
		
		decoder.readEndElement();
};

Name.prototype.to_ccnb = function(/*XMLEncoder*/ encoder)  {
		
		if( this.components ==null ) 
			throw new Error("CANNOT ENCODE EMPTY CONTENT NAME");

		encoder.writeStartElement(this.getElementLabel());
		var count = this.components.length;
		for (var i=0; i < count; i++) {
			encoder.writeElement(CCNProtocolDTags.Component, this.components[i]);
		}
		encoder.writeEndElement();
};

Name.prototype.getElementLabel = function(){
	return CCNProtocolDTags.Name;
};

Name.prototype.add = function(param){
	return this.components.push(param);
};

