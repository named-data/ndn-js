//TODO INCOMPLETE
/*
 * @author: ucla-cs
 * 
 * Encodes CCN object into xml
 */

var Stream = require('stream').Stream;
var TextXMLCodec = require('TextXMLCodec').TextXMLCodec;




var TextXMLEncoder  = function TextXMLEncoder(){


	this.ostream = new String();
};

exports.TextXMLEncoder = TextXMLEncoder;

TextXMLEncoder.prototype.beginEncoding = function(/*OutputStream*/ ostream){
		if (null == ostream)
			throw new IllegalArgumentException("TextXMLEncoder: output stream cannot be null!");
		
		
		/*Start by encoing the begining*/
		//this.IStream = ostream;
		this.ostream.write('<?xml version="1.0" encoding="UTF-8"?>');
};

TextXMLEncoder.prototype.endEncoding =function() {
	this.IStream.end();
}


TextXMLEncoder.prorotype.writeStartElement(/*String*/ tag, /*TreeMap<String, String>*/ attributes) {
		
	
		this.ostream.write('<'+tab);

		if (null != attributes) {
			
			for(var i=0; i<attributes.length;i++){
				this.ostream.write(' '+attributes[i].key +'='+attributes[i].value);
			}
		
			// keySet of a TreeMap is ordered
		}
		this.ostream.write('>');
};

TextXMLEncoder.prototype.writeUString = function(/*String*/ utf8Content) {

		this.ostream.write(utf8Content);

};


TextXMLEncoder.prototype.writeBlob =  function(/*byte []*/ binaryContent, /*int*/ offset, /*int*/ length) {

		this.ostream.write(TextXMLCodec.encodeBinaryElement(binaryContent, offset, length));

};

TextXMLEncoder.prototype.writeElement = function(/*String*/ tag, /*byte[]*/ binaryContent,
			/*TreeMap<String, String>*/ attributes)  {
		
		/*if (null == attributes) {
		
			attributes = new TreeMap<String,String>();
		}*/
		if (!attributes.containsKey(TextXMLCodec.BINARY_ATTRIBUTE)) {
			attributes.put(TextXMLCodec.BINARY_ATTRIBUTE, TextXMLCodec.BINARY_ATTRIBUTE_VALUE);
		}
		super.writeElement(tag, binaryContent, attributes);
}


TextXMLEncoder.prototype.writeEndElement(tag) {

		this.ostream.write('<'+tab+'>');

	};

	
//returns number long
stringToTag = function(/*String*/ tagName) {

	if (null == tagName) {
		return null;
	}
	Long tagVal = null;
	if (null != _dictionaryStack) {
		for (/*XMLDictionary*/ dictionary in _dictionaryStack) {
			tagVal = dictionary.stringToTag(tagName);
			if (null != tagVal) {
				return tagVal;
			}
		}
	}


	if (XMLDictionaryStack.isUnknownTag(tagName)) {
		return XMLDictionaryStack.decodeUnknownTag(tagName);
	}
	return null;
};
	
