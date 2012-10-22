/*
 * @author: ucla-cs
 * See COPYING for copyright and distribution information.
 * This class represents a Name as an array of components where each is a byte array.
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

Name.createNameArray=function(name) {
	var array = name.split('/');
    var colonIndex = array[0].indexOf(':');
    if (colonIndex >= 0) {
        name = name.substr(colonIndex + 1, name.length - colonIndex - 1);
        array = name.split('/');
    }
	
	if(name[0]=="/")
		array=array.slice(1,array.length);		
	if(name[name.length-1]=="/")
		array=array.slice(0,array.length-1);
    
    // Unescape the components.
    for (var i = 0; i < array.length; ++i) {
        var component = unescape(array[i]);
        
        if (component.match(/[^.]/) == null) {
            // Special case for component of only periods.  Remove 3 periods.
            if (component.length <= 3)
                array[i] = "";
            else
                array[i] = component.substr(3, component.length - 3);
        }
        else
            array[i] = component;
    }

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

// Return the escaped name string according to "CCNx URI Scheme".  Does not include "ccnx:".
Name.prototype.to_uri = function() {	
	var result = "";
	
	for(var i = 0; i < this.components.length; ++i)
		result += "/"+ Name.toEscapedString(this.components[i]);
	
	return result;	
};

/**
 * Return component as an escaped string according to "CCNx URI Scheme".
 * We can't use encodeURIComponent because that doesn't encode all the characters we want to.
 */
Name.toEscapedString = function(component) {
    var result = "";
    var gotNonDot = false;
    for (var i = 0; i < component.length; ++i) {
        if (component[i] != 0x2e) {
            gotNonDot = true;
            break;
        }
    }
    if (!gotNonDot) {
        // Special case for component of zero or more periods.  Add 3 periods.
        result = "...";
        for (var i = 0; i < component.length; ++i)
            result += ".";
    }
    else {
        for (var i = 0; i < component.length; ++i) {
            var value = component[i];
            // Check for 0-9, A-Z, a-z, (+), (-), (.), (_)
            if (value >= 0x30 && value <= 0x39 || value >= 0x41 && value <= 0x5a ||
                value >= 0x61 && value <= 0x7a || value == 0x2b || value == 0x2d || 
                value == 0x2e || value == 0x5f)
                result += String.fromCharCode(value);
            else
                result += "%" + (value < 16 ? "0" : "") + value.toString(16).toUpperCase();
        }
    }
    return result;
};
